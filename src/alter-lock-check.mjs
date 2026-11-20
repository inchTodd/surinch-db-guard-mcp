import {
    normalizeTableName,
    splitTopLevelItems,
    stripCommentsPreservingStrings,
    unquoteIdent,
} from './ddl-parser.mjs';

const VOLATILE_DEFAULT_RE = /\bDEFAULT\b[\s\S]*\b(random|clock_timestamp|gen_random_uuid|uuid_generate_v4)\s*\(/i;

export function splitSqlStatements(sql) {
    const statements = [];
    let current = '';
    let i = 0;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];
        if (ch === "'" || ch === '"' || ch === '`') {
            const quote = ch;
            current += ch;
            i += 1;
            while (i < n) {
                const c = sql[i];
                current += c;
                if (c === '\\' && i + 1 < n) {
                    current += sql[i + 1];
                    i += 2;
                    continue;
                }
                if (c === quote) {
                    if (sql[i + 1] === quote) {
                        current += sql[i + 1];
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if (ch === ';') {
            const trimmed = current.trim();
            if (trimmed) statements.push(trimmed);
            current = '';
            i += 1;
            continue;
        }
        current += ch;
        i += 1;
    }
    const last = current.trim();
    if (last) statements.push(last);
    return statements;
}

function parseAlterHeader(stmt) {
    const match = stmt.match(
        /^ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([`"'\w.]+)\s+([\s\S]+)$/i
    );
    if (!match) return null;
    const rawTable = match[1];
    const tableName = normalizeTableName(rawTable);
    const body = match[2].trim();
    return {
        rawTable,
        tableName,
        tableKey: tableName.toLowerCase(),
        body,
    };
}

function collectPgNotValidNotNullChecks(alterStmts) {
    const safeCols = new Set();
    for (const { tableKey, body } of alterStmts) {
        const clauses = splitTopLevelItems(body);
        for (const clause of clauses) {
            if (!/\bNOT\s+VALID\b/i.test(clause)) continue;
            const checkMatch = clause.match(
                /\bCHECK\s*\(\s*([`"'\w]+)\s+IS\s+NOT\s+NULL\s*\)/i
            );
            if (checkMatch) {
                const colKey = unquoteIdent(checkMatch[1]).toLowerCase();
                safeCols.add(`${tableKey}.${colKey}`);
            }
        }
    }
    return safeCols;
}

export function analyzeAlterLockRisks(rawSql, dialect = 'mysql', options = {}) {
    const normalizedDialect = String(dialect || '').trim().toLowerCase();
    const clean = stripCommentsPreservingStrings(String(rawSql || ''));
    const statements = splitSqlStatements(clean);

    const alterEntries = [];
    statements.forEach((stmt, idx) => {
        const parsed = parseAlterHeader(stmt);
        if (parsed) {
            alterEntries.push({
                ...parsed,
                statementIndex: options.statementIndex ?? idx + 1,
                rawStatement: stmt,
            });
        }
    });

    const findings = [];
    if (alterEntries.length === 0) {
        return { alterStatementCount: 0, findings };
    }

    const pgSafeNotNullCols =
        normalizedDialect === 'postgresql'
            ? collectPgNotValidNotNullChecks(alterEntries)
            : new Set();

    for (const entry of alterEntries) {
        const { tableName, tableKey, body, statementIndex } = entry;
        const clauses = splitTopLevelItems(body);

        if (normalizedDialect === 'mysql') {
            const hasAlgorithmInstant = /\bALGORITHM\s*=\s*INSTANT\b/i.test(body);
            const hasOnlineInplace =
                /\bALGORITHM\s*=\s*INPLACE\b/i.test(body) &&
                /\bLOCK\s*=\s*NONE\b/i.test(body);
            const hasExplicitSafeOnline = hasAlgorithmInstant || hasOnlineInplace;

            clauses.forEach((clause, cIdx) => {
                const trimmed = clause.trim();
                const suffix = clauses.length > 1 ? `-${cIdx + 1}` : '';

                if (/^(?:MODIFY|CHANGE)\s+(?:COLUMN\s+)?([`"'\w]+)/i.test(trimmed)) {
                    if (!hasExplicitSafeOnline) {
                        const colMatch = trimmed.match(/^(?:MODIFY|CHANGE)\s+(?:COLUMN\s+)?([`"'\w]+)/i);
                        const colName = unquoteIdent(colMatch?.[1] || '');
                        findings.push({
                            id: `${tableName}.${colName || 'col'}-alter-modify${suffix}`,
                            ruleCode: 'MYSQL_ALTER_MODIFY_COLUMN',
                            severity: 'P1',
                            category: '锁表风险',
                            target: colName ? `${tableName}.${colName}` : tableName,
                            statementIndex,
                            message: `MySQL ALTER TABLE "${tableName}" MODIFY/CHANGE COLUMN "${colName}" may rebuild the table and acquire a metadata/table lock.`,
                            hint: 'Specify ALGORITHM=INSTANT or ALGORITHM=INPLACE, LOCK=NONE where supported, or use gh-ost / pt-osc for online schema migration.',
                        });
                    }
                    return;
                }

                if (/^ADD\s+(?:CONSTRAINT\s+[`"'\w]+\s+)?PRIMARY\s+KEY\b/i.test(trimmed)) {
                    findings.push({
                        id: `${tableName}-alter-add-pk${suffix}`,
                        ruleCode: 'MYSQL_ALTER_ADD_PRIMARY_KEY',
                        severity: 'P0',
                        category: '锁表风险',
                        target: tableName,
                        statementIndex,
                        message: `MySQL ALTER TABLE "${tableName}" ADD PRIMARY KEY rebuilds the clustered index and blocks concurrent writes.`,
                        hint: 'Use gh-ost or pt-osc for online migration, or explicitly verify ALGORITHM=INPLACE, LOCK=NONE in a maintenance window.',
                    });
                    return;
                }

                if (/^ADD\s+(?:CONSTRAINT\s+[`"'\w]+\s+)?FOREIGN\s+KEY\b/i.test(trimmed)) {
                    findings.push({
                        id: `${tableName}-alter-add-fk${suffix}`,
                        ruleCode: 'MYSQL_ALTER_ADD_FOREIGN_KEY',
                        severity: 'P1',
                        category: '锁表风险',
                        target: tableName,
                        statementIndex,
                        message: `MySQL ALTER TABLE "${tableName}" ADD FOREIGN KEY acquires metadata locks on parent and child tables and validates existing rows.`,
                        hint: 'Prefer ALGORITHM=INPLACE, LOCK=NONE (with foreign_key_checks=0 in controlled maintenance) or use gh-ost / pt-osc.',
                    });
                    return;
                }

                if (/^CONVERT\s+TO\s+CHARACTER\s+SET\b/i.test(trimmed)) {
                    findings.push({
                        id: `${tableName}-alter-convert-charset${suffix}`,
                        ruleCode: 'MYSQL_ALTER_CONVERT_CHARSET',
                        severity: 'P0',
                        category: '锁表风险',
                        target: tableName,
                        statementIndex,
                        message: `MySQL ALTER TABLE "${tableName}" CONVERT TO CHARACTER SET forces a full table copy and blocks writes.`,
                        hint: 'Use gh-ost or pt-osc instead of direct ALTER TABLE CONVERT TO CHARACTER SET.',
                    });
                }
            });
        } else if (normalizedDialect === 'postgresql') {
            clauses.forEach((clause, cIdx) => {
                const trimmed = clause.trim();
                const suffix = clauses.length > 1 ? `-${cIdx + 1}` : '';

                const alterTypeMatch = trimmed.match(
                    /^ALTER\s+(?:COLUMN\s+)?([`"'\w]+)\s+(?:SET\s+DATA\s+)?TYPE\b/i
                );
                if (alterTypeMatch) {
                    const colName = unquoteIdent(alterTypeMatch[1]);
                    findings.push({
                        id: `${tableName}.${colName}-pg-alter-type${suffix}`,
                        ruleCode: 'PG_ALTER_COLUMN_TYPE',
                        severity: 'P0',
                        category: '锁表风险',
                        target: `${tableName}.${colName}`,
                        statementIndex,
                        message: `PostgreSQL ALTER TABLE "${tableName}" ALTER COLUMN "${colName}" TYPE acquires an ACCESS EXCLUSIVE lock and rewrites the table.`,
                        hint: 'Use expand-and-contract: add a new column, backfill in batches, swap column names in a short transaction, then drop the old column.',
                    });
                    return;
                }

                const setNotNullMatch = trimmed.match(
                    /^ALTER\s+(?:COLUMN\s+)?([`"'\w]+)\s+SET\s+NOT\s+NULL\b/i
                );
                if (setNotNullMatch) {
                    const colName = unquoteIdent(setNotNullMatch[1]);
                    const colKey = `${tableKey}.${colName.toLowerCase()}`;
                    if (!pgSafeNotNullCols.has(colKey)) {
                        findings.push({
                            id: `${tableName}.${colName}-pg-set-not-null${suffix}`,
                            ruleCode: 'PG_ALTER_SET_NOT_NULL',
                            severity: 'P1',
                            category: '锁表风险',
                            target: `${tableName}.${colName}`,
                            statementIndex,
                            message: `PostgreSQL ALTER TABLE "${tableName}" ALTER COLUMN "${colName}" SET NOT NULL scans the full table under an ACCESS EXCLUSIVE lock.`,
                            hint: `Add CHECK (${colName} IS NOT NULL) NOT VALID, run VALIDATE CONSTRAINT, then execute SET NOT NULL.`,
                        });
                    }
                    return;
                }

                if (/^ADD\s+(?:CONSTRAINT\s+[`"'\w]+\s+)?FOREIGN\s+KEY\b/i.test(trimmed)) {
                    if (!/\bNOT\s+VALID\b/i.test(trimmed)) {
                        findings.push({
                            id: `${tableName}-pg-add-fk-no-not-valid${suffix}`,
                            ruleCode: 'PG_ALTER_ADD_FK_WITHOUT_NOT_VALID',
                            severity: 'P1',
                            category: '锁表风险',
                            target: tableName,
                            statementIndex,
                            message: `PostgreSQL ALTER TABLE "${tableName}" ADD FOREIGN KEY without NOT VALID validates all existing rows while holding heavy table locks (ACCESS EXCLUSIVE / SHARE ROW EXCLUSIVE).`,
                            hint: 'Append NOT VALID to ADD CONSTRAINT ... FOREIGN KEY (...), then run ALTER TABLE ... VALIDATE CONSTRAINT in a separate step.',
                        });
                    }
                    return;
                }

                const addColMatch = trimmed.match(
                    /^ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([`"'\w]+)\s+([\s\S]+)$/i
                );
                if (addColMatch) {
                    const colName = unquoteIdent(addColMatch[1]);
                    const volatileMatch = addColMatch[2].match(VOLATILE_DEFAULT_RE);
                    if (volatileMatch) {
                        const fnName = volatileMatch[1];
                        findings.push({
                            id: `${tableName}.${colName}-pg-volatile-default${suffix}`,
                            ruleCode: 'PG_ALTER_ADD_COL_VOLATILE_DEFAULT',
                            severity: 'P0',
                            category: '锁表风险',
                            target: `${tableName}.${colName}`,
                            statementIndex,
                            message: `PostgreSQL ALTER TABLE "${tableName}" ADD COLUMN "${colName}" with volatile DEFAULT (${fnName}()) forces a full table rewrite under an ACCESS EXCLUSIVE lock.`,
                            hint: 'Add the column nullable without DEFAULT, backfill in batches, then apply ALTER COLUMN ... SET DEFAULT.',
                        });
                    }
                }
            });
        }
    }

    return {
        alterStatementCount: alterEntries.length,
        findings,
    };
}
