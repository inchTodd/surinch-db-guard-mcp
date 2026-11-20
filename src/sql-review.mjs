import { analyzeAlterLockRisks } from './alter-lock-check.mjs';
import { applyRuleConfig, resolveConfig } from './config.mjs';

const WRITE_FIRST_KEYWORDS = new Set([
    'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'REPLACE', 'DROP', 'TRUNCATE',
    'ALTER', 'CREATE', 'RENAME', 'GRANT', 'REVOKE', 'CALL', 'EXEC', 'EXECUTE', 'VACUUM', 'LOCK',
]);

function maskStringsAndComments(sql) {
    let out = '';
    let i = 0;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];
        const next = sql[i + 1];
        if (ch === "'" || ch === '"') {
            const quote = ch;
            out += quote === "'" ? "'__STR__'" : '"__IDENT__"';
            i += 1;
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
                    break;
                }
                i += 1;
            }
            continue;
        }
        if (ch === '-' && next === '-') {
            while (i < n && sql[i] !== '\n') i += 1;
            out += ' ';
            continue;
        }
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i += 1;
            i += 2;
            out += ' ';
            continue;
        }
        out += ch;
        i += 1;
    }
    return out;
}

const SUPPORTED_SQL_DIALECTS = new Set(['mysql', 'postgresql']);
const WRITE_BLOCK_RULE_CODES = new Set(['R01_EXPLAIN_ANALYZE', 'R02_WRITE_OR_DDL', 'R02_DML_NO_WHERE']);

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

    const masked = maskStringsAndComments(trimmed);
    const statements = masked.split(';').map((s) => s.trim()).filter(Boolean);
    if (statements.length === 0) {
        return { ok: false, errorCode: 'NO_STATEMENT', message: 'No executable SQL statement found (comments/whitespace only).' };
    }

    const rawFindings = [];

    statements.forEach((stmt, idx) => {
        const statementIndex = idx + 1;
        const normalized = stmt.replace(/^\(+\s*/, '').trim();
        const firstWord = (normalized.match(/^([a-zA-Z_][a-zA-Z0-9_]*)/)?.[1] || '').toUpperCase();

        if (/^EXPLAIN\s+ANALYZE\b/i.test(normalized) || /^EXPLAIN\s*\([^)]*\bANALYZE\b/i.test(normalized)) {
            rawFindings.push({ id: `stmt-${statementIndex}-explain-analyze`, severity: 'P0', ruleCode: 'R01_EXPLAIN_ANALYZE', statementIndex, message: 'EXPLAIN ANALYZE executes the query in the database.' });
        }

        const cteWriteMatch = firstWord === 'WITH' ? normalized.match(/\)\s*(INSERT|UPDATE|DELETE|MERGE)\b/i) : null;
        if (WRITE_FIRST_KEYWORDS.has(firstWord) || cteWriteMatch) {
            const op = cteWriteMatch ? cteWriteMatch[1].toUpperCase() : firstWord;
            const noWhere = (op === 'DELETE' || op === 'UPDATE') && !/\bWHERE\b/i.test(normalized);
            rawFindings.push({
                id: `stmt-${statementIndex}-write-op`,
                severity: 'P0',
                ruleCode: noWhere ? 'R02_DML_NO_WHERE' : 'R02_WRITE_OR_DDL',
                statementIndex,
                message: noWhere ? `${op} without WHERE clause detected.` : `Write/DDL statement "${op}" violates readonly boundary.`,
            });
        }

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

    const alterAnalysis = analyzeAlterLockRisks(trimmed, normalizedDialect);
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
