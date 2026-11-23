import {
    normalizeTableName,
    parseDdlTables,
    splitSqlStatementsLexical,
    splitTopLevelItems,
    stripCommentsPreservingStrings,
    unquoteIdent,
} from './ddl-parser.mjs';

const VOLATILE_DEFAULT_RE = /\bDEFAULT\b[\s\S]*\b(random|clock_timestamp|gen_random_uuid|uuid_generate_v4)\s*\(/i;

export function splitSqlStatements(sql) {
    return splitSqlStatementsLexical(sql);
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

function parseVarcharInfo(typeStr) {
    const t = String(typeStr || '').trim().toLowerCase();
    if (t === 'text') return { kind: 'text', len: Infinity };
    const m = t.match(/^(?:varchar|character\s+varying)\s*(?:\(\s*(\d+)\s*\))?$/);
    if (!m) return null;
    return { kind: 'varchar', len: m[1] ? Number(m[1]) : Infinity };
}

function isPgVarcharSafeWidening(fromType, toType) {
    const from = parseVarcharInfo(fromType);
    const to = parseVarcharInfo(toType);
    if (!from || !to) return false;
    // Widening varchar(M) -> varchar(N) (N >= M) or varchar(M) -> text does NOT rewrite the table in PG
    return to.len >= from.len;
}

export function analyzeAlterLockRisks(rawSql, dialect = 'mysql', options = {}) {
    const normalizedDialect = String(dialect || '').trim().toLowerCase();
    const clean = stripCommentsPreservingStrings(String(rawSql || ''));
    const statements = splitSqlStatements(clean);

    // Build column type map from any CREATE TABLE statements present in the same script
    const knownColTypes = new Map();
    const parsedTables = parseDdlTables(clean, normalizedDialect);
    for (const tbl of parsedTables) {
        const tKey = tbl.name.toLowerCase();
        for (const col of tbl.columns) {
            knownColTypes.set(`${tKey}.${col.name.toLowerCase()}`, col.rawType);
        }
    }

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

    // Track PG NOT VALID CHECK constraints sequentially so exemption ONLY applies
    // after BOTH `ADD CONSTRAINT <name> CHECK (<col> IS NOT NULL) NOT VALID` AND
    // a subsequent `VALIDATE CONSTRAINT <name>` BEFORE `SET NOT NULL`.
    const pgPendingNotValidChecks = new Map(); // `${tableKey}.${constraintKey}` -> `${tableKey}.${colKey}`
    const pgValidatedNotNullCols = new Set();  // `${tableKey}.${colKey}`

    for (const entry of alterEntries) {
        const { tableName, tableKey, body, statementIndex } = entry;
        const clauses = splitTopLevelItems(body);

        if (normalizedDialect === 'mysql') {
            const hasAlgorithmCopy = /\bALGORITHM\s*=\s*COPY\b/i.test(body);
            const hasLockExclusive = /\bLOCK\s*=\s*EXCLUSIVE\b/i.test(body);
            const hasAlgorithmInstant = /\bALGORITHM\s*=\s*INSTANT\b/i.test(body);
            const hasOnlineInplace =
                /\bALGORITHM\s*=\s*INPLACE\b/i.test(body) &&
                /\bLOCK\s*=\s*NONE\b/i.test(body);
            const hasExplicitSafeOnline = !hasAlgorithmCopy && !hasLockExclusive && (hasAlgorithmInstant || hasOnlineInplace);

            if (hasAlgorithmCopy) {
                findings.push({
                    id: `${tableName}-alter-algorithm-copy-${statementIndex}`,
                    ruleCode: 'MYSQL_ALTER_ALGORITHM_COPY',
                    severity: 'P0',
                    category: '锁表风险',
                    target: tableName,
                    statementIndex,
                    message: `MySQL ALTER TABLE "${tableName}" explicitly specifies ALGORITHM=COPY, which forces a full table copy and blocks concurrent writes.`,
                    hint: 'Avoid ALGORITHM=COPY in production; use ALGORITHM=INSTANT / ALGORITHM=INPLACE, LOCK=NONE or gh-ost / pt-osc.',
                });
            }

            if (hasLockExclusive) {
                findings.push({
                    id: `${tableName}-alter-lock-exclusive-${statementIndex}`,
                    ruleCode: 'MYSQL_ALTER_LOCK_EXCLUSIVE',
                    severity: 'P0',
                    category: '锁表风险',
                    target: tableName,
                    statementIndex,
                    message: `MySQL ALTER TABLE "${tableName}" specifies LOCK=EXCLUSIVE, blocking all concurrent reads and writes.`,
                    hint: 'Use LOCK=NONE where supported or migrate online with gh-ost / pt-osc.',
                });
            }

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

                if (/^DROP\s+PRIMARY\s+KEY\b/i.test(trimmed)) {
                    findings.push({
                        id: `${tableName}-alter-drop-pk${suffix}`,
                        ruleCode: 'MYSQL_ALTER_DROP_PRIMARY_KEY',
                        severity: 'P0',
                        category: '锁表风险',
                        target: tableName,
                        statementIndex,
                        message: `MySQL ALTER TABLE "${tableName}" DROP PRIMARY KEY forces a full table copy (ALGORITHM=COPY) and blocks concurrent writes.`,
                        hint: 'Use gh-ost or pt-osc for online primary key migration instead of direct DROP PRIMARY KEY.',
                    });
                    return;
                }

                if (
                    /^ADD\s+(?:CONSTRAINT\s+[`"'\w]+\s+)?PRIMARY\s+KEY\b/i.test(trimmed) ||
                    (/^ADD\s+(?:COLUMN\s+)?/i.test(trimmed) && /\bPRIMARY\s+KEY\b/i.test(trimmed))
                ) {
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
                    return;
                }

                if (/^(?:FORCE\b|ENGINE\s*=)/i.test(trimmed)) {
                    findings.push({
                        id: `${tableName}-alter-rebuild-engine${suffix}`,
                        ruleCode: 'MYSQL_ALTER_REBUILD_ENGINE',
                        severity: hasExplicitSafeOnline ? 'P1' : 'P0',
                        category: '锁表风险',
                        target: tableName,
                        statementIndex,
                        message: `MySQL ALTER TABLE "${tableName}" (${trimmed.slice(0, 32)}) triggers a full table rebuild and may block concurrent traffic.`,
                        hint: 'Run table rebuilds via gh-ost / pt-osc or specify ALGORITHM=INPLACE, LOCK=NONE in a controlled maintenance window.',
                    });
                }
            });
        } else if (normalizedDialect === 'postgresql') {
            clauses.forEach((clause, cIdx) => {
                const trimmed = clause.trim();
                const suffix = clauses.length > 1 ? `-${cIdx + 1}` : '';

                // Track ADD CONSTRAINT <name> CHECK (<col> IS NOT NULL) NOT VALID
                const addNotValidCheck = trimmed.match(
                    /^ADD\s+CONSTRAINT\s+([`"'\w]+)\s+CHECK\s*\(\s*([`"'\w]+)\s+IS\s+NOT\s+NULL\s*\)\s+NOT\s+VALID\b/i
                );
                if (addNotValidCheck) {
                    const constraintKey = unquoteIdent(addNotValidCheck[1]).toLowerCase();
                    const colKey = unquoteIdent(addNotValidCheck[2]).toLowerCase();
                    pgPendingNotValidChecks.set(`${tableKey}.${constraintKey}`, `${tableKey}.${colKey}`);
                    return;
                }

                // Track VALIDATE CONSTRAINT <name>
                const validateMatch = trimmed.match(/^VALIDATE\s+CONSTRAINT\s+([`"'\w]+)/i);
                if (validateMatch) {
                    const constraintKey = unquoteIdent(validateMatch[1]).toLowerCase();
                    const validatedCol = pgPendingNotValidChecks.get(`${tableKey}.${constraintKey}`);
                    if (validatedCol) {
                        pgValidatedNotNullCols.add(validatedCol);
                    }
                    return;
                }

                // ALTER COLUMN ... TYPE
                const alterTypeMatch = trimmed.match(
                    /^ALTER\s+(?:COLUMN\s+)?([`"'\w]+)\s+(?:SET\s+DATA\s+)?TYPE\s+([^\s;,]+(?:\s+varying)?(?:\s*\([^)]*\))?(?:\s+with(?:out)?\s+time\s+zone)?)([\s\S]*)$/i
                );
                if (alterTypeMatch) {
                    const colName = unquoteIdent(alterTypeMatch[1]);
                    const targetType = alterTypeMatch[2].trim();
                    const tail = alterTypeMatch[3] || '';
                    const hasUsing = /\bUSING\b/i.test(tail);
                    const colKey = `${tableKey}.${colName.toLowerCase()}`;
                    const priorType = knownColTypes.get(colKey);

                    if (!hasUsing && priorType && isPgVarcharSafeWidening(priorType, targetType)) {
                        // Safe metadata-only varchar/text widening in PostgreSQL: no table rewrite!
                        knownColTypes.set(colKey, targetType);
                        return;
                    }

                    const isTargetVarcharOrText = !hasUsing && parseVarcharInfo(targetType) !== null;
                    if (isTargetVarcharOrText && !priorType) {
                        // Unknown prior type: widening varchar->varchar/text doesn't rewrite, but other conversions do
                        findings.push({
                            id: `${tableName}.${colName}-pg-alter-type${suffix}`,
                            ruleCode: 'PG_ALTER_COLUMN_TYPE',
                            severity: 'P1',
                            category: '锁表风险',
                            target: `${tableName}.${colName}`,
                            statementIndex,
                            message: `PostgreSQL ALTER TABLE "${tableName}" ALTER COLUMN "${colName}" TYPE ${targetType} acquires an ACCESS EXCLUSIVE lock and may rewrite the table unless widening an existing varchar/text column.`,
                            hint: 'Verify the prior column type: widening varchar(N) -> varchar(M) (M >= N) or text is metadata-only; otherwise use expand-and-contract.',
                        });
                    } else {
                        findings.push({
                            id: `${tableName}.${colName}-pg-alter-type${suffix}`,
                            ruleCode: 'PG_ALTER_COLUMN_TYPE',
                            severity: 'P0',
                            category: '锁表风险',
                            target: `${tableName}.${colName}`,
                            statementIndex,
                            message: `PostgreSQL ALTER TABLE "${tableName}" ALTER COLUMN "${colName}" TYPE ${targetType} acquires an ACCESS EXCLUSIVE lock and rewrites the table.`,
                            hint: 'Use expand-and-contract: add a new column, backfill in batches, swap column names in a short transaction, then drop the old column.',
                        });
                    }
                    knownColTypes.set(colKey, targetType);
                    return;
                }

                // ALTER COLUMN ... SET NOT NULL
                const setNotNullMatch = trimmed.match(
                    /^ALTER\s+(?:COLUMN\s+)?([`"'\w]+)\s+SET\s+NOT\s+NULL\b/i
                );
                if (setNotNullMatch) {
                    const colName = unquoteIdent(setNotNullMatch[1]);
                    const colKey = `${tableKey}.${colName.toLowerCase()}`;
                    if (!pgValidatedNotNullCols.has(colKey)) {
                        findings.push({
                            id: `${tableName}.${colName}-pg-set-not-null${suffix}`,
                            ruleCode: 'PG_ALTER_SET_NOT_NULL',
                            severity: 'P1',
                            category: '锁表风险',
                            target: `${tableName}.${colName}`,
                            statementIndex,
                            message: `PostgreSQL ALTER TABLE "${tableName}" ALTER COLUMN "${colName}" SET NOT NULL scans the full table under an ACCESS EXCLUSIVE lock.`,
                            hint: `Add CONSTRAINT chk_${colName}_nn CHECK (${colName} IS NOT NULL) NOT VALID, run VALIDATE CONSTRAINT chk_${colName}_nn, then execute SET NOT NULL.`,
                        });
                    }
                    return;
                }

                // ADD [CONSTRAINT ...] FOREIGN KEY without NOT VALID
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

                // ADD [CONSTRAINT ...] CHECK (...) without NOT VALID
                if (/^ADD\s+(?:CONSTRAINT\s+[`"'\w]+\s+)?CHECK\s*\(/i.test(trimmed)) {
                    if (!/\bNOT\s+VALID\b/i.test(trimmed)) {
                        findings.push({
                            id: `${tableName}-pg-add-check-no-not-valid${suffix}`,
                            ruleCode: 'PG_ALTER_ADD_CHECK_WITHOUT_NOT_VALID',
                            severity: 'P1',
                            category: '锁表风险',
                            target: tableName,
                            statementIndex,
                            message: `PostgreSQL ALTER TABLE "${tableName}" ADD CHECK constraint without NOT VALID scans the entire table under an ACCESS EXCLUSIVE lock.`,
                            hint: 'Append NOT VALID to ADD CONSTRAINT ... CHECK (...), then run ALTER TABLE ... VALIDATE CONSTRAINT in a separate step.',
                        });
                    }
                    return;
                }

                // ADD COLUMN ... (check volatile DEFAULT and inline REFERENCES)
                const addColMatch = trimmed.match(
                    /^ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([`"'\w]+)\s+([\s\S]+)$/i
                );
                if (addColMatch) {
                    const colName = unquoteIdent(addColMatch[1]);
                    const colDef = addColMatch[2];
                    const volatileMatch = colDef.match(VOLATILE_DEFAULT_RE);
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
                    if (/\bREFERENCES\s+[`"'\w.]+/i.test(colDef) && !/\bNOT\s+VALID\b/i.test(colDef)) {
                        findings.push({
                            id: `${tableName}.${colName}-pg-inline-fk${suffix}`,
                            ruleCode: 'PG_ALTER_ADD_FK_WITHOUT_NOT_VALID',
                            severity: 'P1',
                            category: '锁表风险',
                            target: `${tableName}.${colName}`,
                            statementIndex,
                            message: `PostgreSQL ALTER TABLE "${tableName}" ADD COLUMN "${colName}" with inline REFERENCES validates the foreign key immediately under heavy table locks.`,
                            hint: 'Add the column first, then ADD CONSTRAINT ... FOREIGN KEY (...) NOT VALID, followed by VALIDATE CONSTRAINT.',
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
