import { analyzeAlterLockRisks } from './alter-lock-check.mjs';
import { applyRuleConfig, resolveConfig } from './config.mjs';
import { matchDollarQuoteTag } from './ddl-parser.mjs';

const SUPPORTED_SQL_DIALECTS = new Set(['mysql', 'postgresql']);

// Allowlist-first (default deny): only explicitly readonly statement heads may pass.
const READONLY_ALLOWED_FIRST_KEYWORDS = new Set([
    'SELECT',
    'WITH',
    'SHOW',
    'EXPLAIN',
    'DESCRIBE',
    'DESC',
    'VALUES',
    'TABLE',
]);

// Known mutating / administrative / procedural statements for clearer diagnostics
const KNOWN_WRITE_OR_ADMIN_KEYWORDS = new Set([
    'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'REPLACE', 'DROP', 'TRUNCATE',
    'ALTER', 'CREATE', 'RENAME', 'GRANT', 'REVOKE', 'CALL', 'EXEC', 'EXECUTE',
    'VACUUM', 'LOCK', 'UNLOCK', 'DO', 'COPY', 'LOAD', 'FLUSH', 'SET', 'RESET',
    'KILL', 'STOP', 'START', 'PURGE', 'REPAIR', 'OPTIMIZE', 'IMPORT', 'PREPARE',
    'DEALLOCATE', 'DISCARD', 'LISTEN', 'NOTIFY', 'UNLISTEN', 'CHECKPOINT',
    'CLUSTER', 'REINDEX', 'REFRESH', 'ANALYZE', 'COMMENT', 'SECURITY', 'HANDLER',
    'BEGIN', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'RELEASE', 'XA',
]);

// Side-effect / DoS / file-IO / session-control functions forbidden inside readonly SELECT/WITH
const SIDE_EFFECT_FUNCTIONS = [
    // PostgreSQL
    'pg_sleep', 'pg_sleep_for', 'pg_sleep_until',
    'pg_terminate_backend', 'pg_cancel_backend',
    'pg_reload_conf', 'pg_rotate_logfile', 'pg_switch_wal',
    'pg_read_file', 'pg_read_binary_file', 'pg_ls_dir', 'pg_stat_file',
    'lo_import', 'lo_export', 'lo_unlink', 'lo_create', 'lo_open', 'lo_put', 'lo_from_bytea',
    'dblink', 'dblink_exec', 'dblink_connect', 'dblink_connect_u', 'dblink_send_query',
    'set_config', 'pg_notify', 'pg_create_restore_point',
    'pg_advisory_lock', 'pg_advisory_xact_lock', 'pg_try_advisory_lock', 'pg_advisory_unlock',
    'nextval', 'setval', 'query_to_xml',
    // MySQL
    'sleep', 'benchmark', 'get_lock', 'release_lock', 'release_all_locks',
    'load_file', 'sys_exec', 'sys_eval', 'master_pos_wait', 'source_pos_wait',
];

const SIDE_EFFECT_FUNC_RE = new RegExp(`\\b(${SIDE_EFFECT_FUNCTIONS.join('|')})\\s*\\(`, 'i');

const WRITE_BLOCK_RULE_CODES = new Set([
    'R01_EXPLAIN_ANALYZE',
    'R02_WRITE_OR_DDL',
    'R02_DML_NO_WHERE',
    'R02_SIDE_EFFECT_FUNC',
    'R02_UNSAFE_OR_UNSUPPORTED_STMT',
    'R02_UNPARSEABLE_OR_UNCLOSED',
]);

/**
 * Lexically mask string literals, identifiers, dollar-quoted strings, and comments
 * while splitting top-level statements cleanly. Detects unclosed quotes/comments and
 * MySQL conditional executable comments (/*!...*\/).
 */
function maskAndSplitSql(sql, dialect) {
    let out = '';
    let i = 0;
    const n = sql.length;
    let lexicalError = null;
    let hasMysqlConditionalComment = false;

    while (i < n) {
        const ch = sql[i];
        const next = sql[i + 1];

        // PostgreSQL dollar-quoted string ($tag$...$tag$)
        if (ch === '$') {
            const tag = matchDollarQuoteTag(sql, i);
            if (tag) {
                const closeIdx = sql.indexOf(tag, i + tag.length);
                if (closeIdx < 0) {
                    lexicalError = `Unclosed dollar-quoted block starting with "${tag}".`;
                    out += ' __UNCLOSED_DOLLAR__ ';
                    break;
                }
                out += " '__DOLLAR_STR__' ";
                i = closeIdx + tag.length;
                continue;
            }
        }

        if (ch === "'" || ch === '"' || ch === '`') {
            const quote = ch;
            out += quote === "'" ? "'__STR__'" : '"__IDENT__"';
            i += 1;
            let closed = false;
            while (i < n) {
                const c = sql[i];
                if (c === '\\' && i + 1 < n) {
                    i += 2;
                    continue;
                }
                if (c === quote) {
                    if (sql[i + 1] === quote) {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if (!closed) {
                lexicalError = `Unclosed ${quote} literal/identifier.`;
                break;
            }
            continue;
        }

        if (ch === '-' && next === '-') {
            while (i < n && sql[i] !== '\n') i += 1;
            out += ' ';
            continue;
        }

        if (dialect === 'mysql' && ch === '#') {
            while (i < n && sql[i] !== '\n') i += 1;
            out += ' ';
            continue;
        }

        if (ch === '/' && next === '*') {
            // MySQL executable conditional comment /*!50000 ... */
            if (sql[i + 2] === '!') {
                hasMysqlConditionalComment = true;
                const endIdx = sql.indexOf('*/', i + 3);
                if (endIdx < 0) {
                    lexicalError = 'Unclosed MySQL conditional comment.';
                    break;
                }
                const inner = sql.slice(i + 3, endIdx).replace(/^\d+\s*/, '');
                out += ` ${inner} `;
                i = endIdx + 2;
                continue;
            }
            i += 2;
            let closed = false;
            while (i < n) {
                if (sql[i] === '*' && sql[i + 1] === '/') {
                    i += 2;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if (!closed) {
                lexicalError = 'Unclosed block comment /* ... */.';
                break;
            }
            out += ' ';
            continue;
        }

        out += ch;
        i += 1;
    }

    const statements = out.split(';').map((s) => s.trim()).filter(Boolean);
    return { statements, lexicalError, hasMysqlConditionalComment };
}

/**
 * Determine whether an EXPLAIN statement actually executes the query (ANALYZE).
 * Correctly handles `EXPLAIN (ANALYZE false)` / `EXPLAIN (ANALYZE off)` / `EXPLAIN (ANALYZE 0)` (no false positive).
 */
function isExplainAnalyze(normalized) {
    if (/^EXPLAIN\s+ANALYZE\b/i.test(normalized)) {
        return true;
    }
    const optMatch = normalized.match(/^EXPLAIN\s*\(([^)]*)\)/i);
    if (!optMatch) return false;
    const opts = optMatch[1];
    const analyzeMatch = opts.match(/\bANALYZE(?:\s+(TRUE|FALSE|ON|OFF|1|0))?\b/i);
    if (!analyzeMatch) return false;
    const val = (analyzeMatch[1] || 'TRUE').toUpperCase();
    return val === 'TRUE' || val === 'ON' || val === '1';
}

function stripExplainPrefix(normalized) {
    return normalized
        .replace(/^EXPLAIN\s*(?:\([^)]*\)\s*)?(?:ANALYZE\s+)?(?:VERBOSE\s+)?(?:FORMAT\s*=\s*\w+\s+)?/i, '')
        .replace(/^\(+\s*/, '')
        .trim();
}

export function reviewSqlReadonly(rawSql, dialect = 'mysql', options = {}) {
    const normalizedDialect = String(dialect || '').trim().toLowerCase();
    if (!SUPPORTED_SQL_DIALECTS.has(normalizedDialect)) {
        return {
            ok: false,
            errorCode: 'UNSUPPORTED_DIALECT',
            message: `Unsupported SQL dialect "${dialect}". Supported: mysql, postgresql.`,
        };
    }

    const cfgRes = resolveConfig(options?.config);
    if (!cfgRes.ok) return cfgRes;
    const config = cfgRes.config;

    const trimmed = String(rawSql || '').trim();
    if (!trimmed) {
        return { ok: false, errorCode: 'EMPTY_INPUT', message: 'Input SQL is empty.' };
    }

    const { statements, lexicalError } = maskAndSplitSql(trimmed, normalizedDialect);
    if (lexicalError) {
        const rawFindings = [{
            id: 'stmt-1-lexical-error',
            severity: 'P0',
            ruleCode: 'R02_UNPARSEABLE_OR_UNCLOSED',
            statementIndex: 1,
            message: `Unparseable SQL cannot be verified as readonly: ${lexicalError}`,
        }];
        const findings = applyRuleConfig(rawFindings, config);
        return {
            ok: true,
            dialect: normalizedDialect,
            statementCount: Math.max(statements.length, 1),
            readonlySafe: false,
            verdict: 'WRITE_OR_DDL_BLOCKED',
            findings,
            counts: {
                p0: findings.filter((f) => f.severity === 'P0').length,
                p1: findings.filter((f) => f.severity === 'P1').length,
                p2: findings.filter((f) => f.severity === 'P2').length,
            },
        };
    }

    if (statements.length === 0) {
        return { ok: false, errorCode: 'NO_STATEMENT', message: 'No executable SQL statement found (comments/whitespace only).' };
    }

    const rawFindings = [];

    statements.forEach((stmt, idx) => {
        const statementIndex = idx + 1;
        const normalized = stmt.replace(/^\(+\s*/, '').trim();
        const firstWord = (normalized.match(/^([a-zA-Z_][a-zA-Z0-9_]*)/)?.[1] || '').toUpperCase();

        // 1. EXPLAIN ANALYZE detection (correctly ignores EXPLAIN (ANALYZE false|off|0))
        const explainAnalyze = firstWord === 'EXPLAIN' && isExplainAnalyze(normalized);
        if (explainAnalyze) {
            rawFindings.push({
                id: `stmt-${statementIndex}-explain-analyze`,
                severity: 'P0',
                ruleCode: 'R01_EXPLAIN_ANALYZE',
                statementIndex,
                message: 'EXPLAIN ANALYZE executes the query in the database.',
            });
        }

        // Inspect effective body (if EXPLAIN without ANALYZE wraps a write, note it; if EXPLAIN ANALYZE wraps a write, also flag the write)
        const targetStmt = firstWord === 'EXPLAIN' ? stripExplainPrefix(normalized) : normalized;
        const targetFirstWord = (targetStmt.match(/^([a-zA-Z_][a-zA-Z0-9_]*)/)?.[1] || '').toUpperCase();

        // 2. Allowlist-first (default deny) classification
        if (!READONLY_ALLOWED_FIRST_KEYWORDS.has(firstWord)) {
            if (KNOWN_WRITE_OR_ADMIN_KEYWORDS.has(firstWord)) {
                const noWhere = (firstWord === 'DELETE' || firstWord === 'UPDATE') && !/\bWHERE\b/i.test(normalized);
                rawFindings.push({
                    id: `stmt-${statementIndex}-write-op`,
                    severity: 'P0',
                    ruleCode: noWhere ? 'R02_DML_NO_WHERE' : 'R02_WRITE_OR_DDL',
                    statementIndex,
                    message: noWhere
                        ? `${firstWord} without WHERE clause detected.`
                        : `Write/DDL/admin statement "${firstWord}" violates readonly boundary.`,
                });
            } else {
                rawFindings.push({
                    id: `stmt-${statementIndex}-unlisted-stmt`,
                    severity: 'P0',
                    ruleCode: 'R02_UNSAFE_OR_UNSUPPORTED_STMT',
                    statementIndex,
                    message: `Statement starting with "${firstWord || '(unknown)'}" is not in the readonly allowlist (SELECT, readonly WITH, SHOW, DESCRIBE, non-ANALYZE EXPLAIN).`,
                });
            }
        } else if (firstWord === 'EXPLAIN' && explainAnalyze && targetFirstWord && !READONLY_ALLOWED_FIRST_KEYWORDS.has(targetFirstWord)) {
            const noWhere = (targetFirstWord === 'DELETE' || targetFirstWord === 'UPDATE') && !/\bWHERE\b/i.test(targetStmt);
            rawFindings.push({
                id: `stmt-${statementIndex}-explain-write-op`,
                severity: 'P0',
                ruleCode: noWhere ? 'R02_DML_NO_WHERE' : 'R02_WRITE_OR_DDL',
                statementIndex,
                message: noWhere
                    ? `EXPLAIN ANALYZE executes ${targetFirstWord} without WHERE clause.`
                    : `EXPLAIN ANALYZE executes write/DDL statement "${targetFirstWord}".`,
            });
        } else {
            // Inside allowlisted SELECT / WITH / EXPLAIN, check for hidden writes & side effects
            const inspectSql = firstWord === 'EXPLAIN' ? targetStmt : normalized;
            const inspectHead = firstWord === 'EXPLAIN' ? targetFirstWord : firstWord;

            // 2a. Data-modifying CTEs (BOTH inside CTE body `AS (DELETE/INSERT/UPDATE/MERGE ...)` AND trailing `...) INSERT/UPDATE/DELETE/MERGE`)
            if (inspectHead === 'WITH') {
                const cteBodyWrite = inspectSql.match(/\bAS\s*(?:(?:NOT\s+)?MATERIALIZED\s*)?\(\s*(INSERT|UPDATE|DELETE|MERGE)\b/i);
                const cteTailWrite = inspectSql.match(/\)\s*(INSERT|UPDATE|DELETE|MERGE)\b/i);
                const cteDmlClause = inspectSql.match(/\b(INSERT\s+INTO|DELETE\s+FROM|MERGE\s+INTO)\b/i);
                const cteMatch = cteBodyWrite || cteTailWrite || cteDmlClause;
                if (cteMatch) {
                    const op = cteMatch[1].split(/\s+/)[0].toUpperCase();
                    const noWhere = (op === 'DELETE' || op === 'UPDATE') && !/\bWHERE\b/i.test(inspectSql);
                    rawFindings.push({
                        id: `stmt-${statementIndex}-cte-write-op`,
                        severity: 'P0',
                        ruleCode: noWhere ? 'R02_DML_NO_WHERE' : 'R02_WRITE_OR_DDL',
                        statementIndex,
                        message: `Data-modifying CTE (${op}) violates readonly boundary.`,
                    });
                }
            }

            // 2b. SELECT ... INTO (creates table in PG, writes file/var in MySQL)
            if ((inspectHead === 'SELECT' || inspectHead === 'WITH') && /\bSELECT\b[\s\S]*\bINTO\s+(?:OUTFILE|DUMPFILE|TEMPORARY|TEMP|UNLOGGED|TABLE|@|[a-zA-Z_"`])/i.test(inspectSql)) {
                rawFindings.push({
                    id: `stmt-${statementIndex}-select-into`,
                    severity: 'P0',
                    ruleCode: 'R02_WRITE_OR_DDL',
                    statementIndex,
                    message: 'SELECT ... INTO creates a table or writes output/file and violates readonly boundary.',
                });
            }

            // 2c. Row-locking SELECT clauses (FOR UPDATE / FOR SHARE / LOCK IN SHARE MODE)
            if (/\bFOR\s+(?:NO\s+KEY\s+UPDATE|UPDATE|KEY\s+SHARE|SHARE)\b/i.test(inspectSql) || /\bLOCK\s+IN\s+SHARE\s+MODE\b/i.test(inspectSql)) {
                rawFindings.push({
                    id: `stmt-${statementIndex}-row-lock`,
                    severity: 'P0',
                    ruleCode: 'R02_WRITE_OR_DDL',
                    statementIndex,
                    message: 'Row-locking SELECT clause (FOR UPDATE / FOR SHARE / LOCK IN SHARE MODE) violates strict readonly boundary.',
                });
            }

            // 2d. Side-effect / DoS / file-I/O functions
            const funcMatch = inspectSql.match(SIDE_EFFECT_FUNC_RE);
            if (funcMatch) {
                rawFindings.push({
                    id: `stmt-${statementIndex}-side-effect-func`,
                    severity: 'P0',
                    ruleCode: 'R02_SIDE_EFFECT_FUNC',
                    statementIndex,
                    message: `Side-effect or privileged function "${funcMatch[1]}()" violates readonly boundary.`,
                });
            }
        }

        // 3. Query anti-patterns (P1 / P2)
        if (/\bSELECT\s+\*/i.test(normalized) && !/\bCOUNT\s*\(\s*\*\s*\)/i.test(normalized)) {
            rawFindings.push({ id: `stmt-${statementIndex}-select-star`, severity: 'P1', ruleCode: 'R03_SELECT_STAR', statementIndex, message: 'SELECT * detected.' });
        }
        if (/\bNOT\s+IN\s*\(\s*SELECT\b/i.test(normalized)) {
            rawFindings.push({ id: `stmt-${statementIndex}-not-in-subquery`, severity: 'P1', ruleCode: 'R05_NOT_IN_NULL_TRAP', statementIndex, message: 'NOT IN (SELECT ...) has NULL trap risk; prefer NOT EXISTS.' });
        }
        if (/\bWHERE\b[\s\S]*\b(?:DATE|YEAR|MONTH|SUBSTR|SUBSTRING|LOWER|UPPER|COALESCE|TO_CHAR|DATE_FORMAT)\s*\(/i.test(normalized)) {
            rawFindings.push({ id: `stmt-${statementIndex}-func-on-column`, severity: 'P1', ruleCode: 'R06_FUNC_ON_FILTER_COL', statementIndex, message: 'Function applied to filter column in WHERE may disable index usage.' });
        }
        const offsetVal = Number(normalized.match(/\bOFFSET\s+(\d+)/i)?.[1] || normalized.match(/\bLIMIT\s+(\d+)\s*,\s*\d+/i)?.[1] || 0);
        if (offsetVal >= 1000) {
            rawFindings.push({ id: `stmt-${statementIndex}-deep-pagination`, severity: 'P1', ruleCode: 'R07_DEEP_PAGINATION', statementIndex, message: `Deep pagination OFFSET=${offsetVal} detected.` });
        }
        if (normalizedDialect === 'postgresql' && /\bSELECT\b/i.test(normalized) && /\bCOUNT\s*\([^)]*\)\s*\/\s*COUNT\s*\([^)]*\)/i.test(normalized) && !/::\s*(?:numeric|decimal|float|double)/i.test(normalized)) {
            rawFindings.push({ id: `stmt-${statementIndex}-pg-int-div`, severity: 'P2', ruleCode: 'R08_PG_INT_DIVISION', statementIndex, message: 'PostgreSQL integer division truncates ratios to 0; cast to ::numeric.' });
        }
    });

    const alterAnalysis = analyzeAlterLockRisks(trimmed, normalizedDialect, { dbVersion: options?.dbVersion });
    for (const af of alterAnalysis.findings) {
        rawFindings.push(af);
    }

    const noCommentRaw = trimmed.replace(/--[^\n]*/g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
    noCommentRaw.split(';').map((s) => s.trim()).filter(Boolean).forEach((rawStmt, idx) => {
        if (/\b(?:I?LIKE)\s+'%[^']*'/i.test(rawStmt)) {
            rawFindings.push({ id: `stmt-${idx + 1}-leading-wildcard`, severity: 'P2', ruleCode: 'R04_LEADING_WILDCARD', statementIndex: idx + 1, message: "Leading wildcard LIKE '%...' disables B-Tree index." });
        }
    });

    const findings = applyRuleConfig(rawFindings, config);

    const severityRank = { P0: 0, P1: 1, P2: 2 };
    findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || (a.statementIndex || 0) - (b.statementIndex || 0));
    const p0 = findings.filter((f) => f.severity === 'P0').length;
    const p1 = findings.filter((f) => f.severity === 'P1').length;
    const p2 = findings.filter((f) => f.severity === 'P2').length;
    const hasWriteBlock = findings.some((f) => WRITE_BLOCK_RULE_CODES.has(f.ruleCode));

    return {
        ok: true,
        dialect: normalizedDialect,
        statementCount: statements.length,
        readonlySafe: !hasWriteBlock && p0 === 0,
        verdict: hasWriteBlock || p0 > 0 ? 'WRITE_OR_DDL_BLOCKED' : p1 + p2 > 0 ? 'READONLY_WITH_WARNINGS' : 'SAFE_READONLY',
        findings,
        counts: { p0, p1, p2 },
    };
}
