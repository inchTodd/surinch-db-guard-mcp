import { SUPPORTED_DDL_DIALECTS, parseDdlTables } from './ddl-parser.mjs';

const MONEY_NAME_RE = /(?:^|_)(amount|amt|price|fee|cost|balance|pay|revenue|profit|total|gmv|money|salary|tax)(?:$|_)/i;
const FLOAT_TYPE_RE = /^(?:float|float4|float8|double|double\s+precision|real)\b/i;
const AUDIT_COL_RE = /^(?:created_at|updated_at|create_time|update_time|gmt_create|gmt_modified|sync_time|etl_time|biz_date|dt)$/i;
const SNAKE_CASE_RE = /^[a-z][a-z0-9_]*$/;

function toSnakeLike(name) {
    return String(name || '').replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

export function analyzeDdlGovernance(rawSql, dialect = 'mysql') {
    const normalizedDialect = String(dialect || '').trim().toLowerCase();
    if (!SUPPORTED_DDL_DIALECTS.has(normalizedDialect)) {
        return {
            ok: false,
            errorCode: 'UNSUPPORTED_DIALECT',
            message: `Unsupported DDL dialect "${dialect}". Supported: mysql, postgresql, doris.`,
        };
    }

    const trimmed = String(rawSql || '').trim();
    if (!trimmed) {
        return { ok: false, errorCode: 'EMPTY_INPUT', message: 'Input DDL is empty.' };
    }

    const parsedTables = parseDdlTables(trimmed, normalizedDialect);
    if (parsedTables.length === 0) {
        return { ok: false, errorCode: 'NO_CREATE_TABLE', message: 'No valid CREATE TABLE statement found.' };
    }

    const tables = [];
    const findings = [];
    let totalCols = 0;
    let totalCommentedCols = 0;
    let snakeOkCols = 0;
    let totalTypeIssues = 0;

    for (const pt of parsedTables) {
        const tableName = pt.name;
        const cols = pt.columns;
        const hasPk = pt.hasPrimaryKey;
        const hasTableComment = pt.hasTableComment;
        const hasAuditTimestamp = cols.some((c) => AUDIT_COL_RE.test(c.name));
        const commentedCount = cols.filter((c) => c.hasInlineComment).length;

        totalCols += cols.length;
        totalCommentedCols += commentedCount;

        if (!SNAKE_CASE_RE.test(tableName)) {
            findings.push({ id: `${tableName}-table-naming`, severity: 'P2', category: '命名规范', target: tableName, message: `Table "${tableName}" is not lowercase snake_case.` });
        }
        if (!hasPk) {
            findings.push({ id: `${tableName}-missing-pk`, severity: 'P0', category: '主键与约束', target: tableName, message: `Table "${tableName}" has no PRIMARY KEY or Doris data model key.` });
        }
        if (!hasTableComment) {
            findings.push({ id: `${tableName}-missing-table-comment`, severity: 'P1', category: '注释覆盖', target: tableName, message: `Table "${tableName}" is missing a table COMMENT.` });
        }
        if (!hasAuditTimestamp && cols.length > 0) {
            findings.push({ id: `${tableName}-missing-audit-ts`, severity: 'P1', category: '审计与可监控', target: tableName, message: `Table "${tableName}" lacks an audit/freshness timestamp column.` });
        }

        for (const col of cols) {
            if (SNAKE_CASE_RE.test(col.name)) snakeOkCols += 1;
            else findings.push({ id: `${tableName}.${col.name}-naming`, severity: 'P2', category: '命名规范', target: `${tableName}.${col.name}`, message: `Column "${col.name}" is not lowercase snake_case.` });

            if (!col.hasInlineComment) {
                findings.push({ id: `${tableName}.${col.name}-comment`, severity: 'P1', category: '注释覆盖', target: `${tableName}.${col.name}`, message: `Column "${tableName}.${col.name}" is missing a COMMENT.` });
            }
            if (MONEY_NAME_RE.test(toSnakeLike(col.name)) && FLOAT_TYPE_RE.test(col.rawType)) {
                totalTypeIssues += 1;
                findings.push({ id: `${tableName}.${col.name}-float-money`, severity: 'P0', category: '类型精度', target: `${tableName}.${col.name}`, message: `Monetary column "${col.name}" uses floating-point type "${col.rawType}". Use DECIMAL/NUMERIC.` });
            } else if (normalizedDialect === 'mysql' && /^varchar$/i.test(col.rawType.trim())) {
                totalTypeIssues += 1;
                findings.push({ id: `${tableName}.${col.name}-varchar-len`, severity: 'P1', category: '类型精度', target: `${tableName}.${col.name}`, message: `MySQL VARCHAR column "${col.name}" is missing explicit length.` });
            }
        }

        tables.push({
            name: tableName,
            columnCount: cols.length,
            hasPrimaryKey: hasPk,
            inheritedLike: pt.inheritedLike,
            hasTableComment,
            commentedColumns: commentedCount,
            hasAuditTimestamp,
        });
    }

    const safeCols = Math.max(totalCols, 1);
    const safeTables = Math.max(tables.length, 1);
    const namingScore = Math.round(((snakeOkCols + tables.filter((t) => SNAKE_CASE_RE.test(t.name)).length) / (safeCols + safeTables)) * 100);
    const commentScore = Math.round(((totalCommentedCols + tables.filter((t) => t.hasTableComment).length) / (safeCols + safeTables)) * 100);
    const pkScore = Math.round((tables.filter((t) => t.hasPrimaryKey).length / safeTables) * 100);
    const monitoringScore = Math.round((tables.filter((t) => t.hasAuditTimestamp).length / safeTables) * 100);
    const typeScore = Math.max(0, Math.round(100 - (totalTypeIssues / safeCols) * 200));

    const dimensions = [
        { key: 'naming', weightPct: 25, score: namingScore, weighted: Number((namingScore * 0.25).toFixed(2)) },
        { key: 'comments', weightPct: 20, score: commentScore, weighted: Number((commentScore * 0.2).toFixed(2)) },
        { key: 'primaryKey', weightPct: 20, score: pkScore, weighted: Number((pkScore * 0.2).toFixed(2)) },
        { key: 'monitoring', weightPct: 20, score: monitoringScore, weighted: Number((monitoringScore * 0.2).toFixed(2)) },
        { key: 'types', weightPct: 15, score: typeScore, weighted: Number((typeScore * 0.15).toFixed(2)) },
    ];
    const totalScore = Math.round(dimensions.reduce((acc, d) => acc + d.weighted, 0));
    const severityRank = { P0: 0, P1: 1, P2: 2 };
    findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

    return {
        ok: true,
        dialect: normalizedDialect,
        tableCount: tables.length,
        columnCount: totalCols,
        totalScore,
        dimensions,
        tables,
        findings,
        counts: {
            p0: findings.filter((f) => f.severity === 'P0').length,
            p1: findings.filter((f) => f.severity === 'P1').length,
            p2: findings.filter((f) => f.severity === 'P2').length,
        },
    };
}
