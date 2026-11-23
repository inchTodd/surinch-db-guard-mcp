import {
    SUPPORTED_DDL_DIALECTS,
    findUnparsedDdlStatements,
    parseDdlTables,
} from './ddl-parser.mjs';
import { analyzeAlterLockRisks } from './alter-lock-check.mjs';
import { applyRuleConfig, resolveConfig } from './config.mjs';

const MONEY_NAME_RE = /(?:^|_)(amount|amt|price|fee|cost|balance|pay|revenue|profit|total|gmv|money|salary|tax)(?:$|_)/i;
const FLOAT_TYPE_RE = /^(?:float|float4|float8|double|double\s+precision|real)\b/i;
const AUDIT_COL_RE = /^(?:created_at|updated_at|create_time|update_time|gmt_create|gmt_modified|sync_time|etl_time|biz_date|dt)$/i;
const SNAKE_CASE_RE = /^[a-z][a-z0-9_]*$/;

function toSnakeLike(name) {
    return String(name || '').replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

export function analyzeDdlGovernance(rawSql, dialect = 'mysql', options = {}) {
    const normalizedDialect = String(dialect || '').trim().toLowerCase();
    if (!SUPPORTED_DDL_DIALECTS.has(normalizedDialect)) {
        return {
            ok: false,
            errorCode: 'UNSUPPORTED_DIALECT',
            message: `Unsupported DDL dialect "${dialect}". Supported: mysql, postgresql, doris.`,
        };
    }

    const cfgRes = resolveConfig(options?.config);
    if (!cfgRes.ok) return cfgRes;
    const config = cfgRes.config;

    const trimmed = String(rawSql || '').trim();
    if (!trimmed) {
        return { ok: false, errorCode: 'EMPTY_INPUT', message: 'Input DDL is empty.' };
    }

    const parsedTables = parseDdlTables(trimmed, normalizedDialect);
    const alterAnalysis = analyzeAlterLockRisks(trimmed, normalizedDialect, { dbVersion: options?.dbVersion });
    const unparsedStatements = findUnparsedDdlStatements(trimmed);

    if (parsedTables.length === 0 && alterAnalysis.alterStatementCount === 0) {
        // Distinguish unsupported CREATE TABLE variants (e.g. CTAS) from non-DDL input
        if (unparsedStatements.some((u) => u.isCreateTableVariant)) {
            return {
                ok: false,
                errorCode: 'UNPARSED_STATEMENT',
                message: `Unsupported or unparsed DDL statement detected: "${unparsedStatements[0].preview}".`,
                unparsedStatements,
            };
        }
        return { ok: false, errorCode: 'NO_CREATE_TABLE', message: 'No valid CREATE TABLE or ALTER TABLE statement found.' };
    }

    // Never silently ignore unrecognized statements alongside valid DDL (eliminates C3 false green)
    if (unparsedStatements.length > 0) {
        return {
            ok: false,
            errorCode: 'UNPARSED_STATEMENT',
            message: `Found ${unparsedStatements.length} unrecognized/unparsed statement(s) that cannot be safely scored (first: "${unparsedStatements[0].preview}").`,
            unparsedStatements,
        };
    }

    const tables = [];
    const rawFindings = [];
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
            rawFindings.push({
                id: `${tableName}-table-naming`,
                ruleCode: 'DDL_TABLE_NAMING',
                severity: 'P2',
                category: '命名规范',
                target: tableName,
                message: `Table "${tableName}" is not lowercase snake_case.`,
            });
        }
        if (!hasPk) {
            rawFindings.push({
                id: `${tableName}-missing-pk`,
                ruleCode: 'DDL_MISSING_PK',
                severity: 'P0',
                category: '主键与约束',
                target: tableName,
                message: `Table "${tableName}" has no PRIMARY KEY or Doris data model key.`,
            });
        }
        if (!hasTableComment) {
            rawFindings.push({
                id: `${tableName}-missing-table-comment`,
                ruleCode: 'DDL_MISSING_TABLE_COMMENT',
                severity: 'P1',
                category: '注释覆盖',
                target: tableName,
                message: `Table "${tableName}" is missing a table COMMENT.`,
            });
        }
        if (!hasAuditTimestamp && cols.length > 0) {
            rawFindings.push({
                id: `${tableName}-missing-audit-ts`,
                ruleCode: 'DDL_MISSING_AUDIT_TS',
                severity: 'P1',
                category: '审计与可监控',
                target: tableName,
                message: `Table "${tableName}" lacks an audit/freshness timestamp column.`,
            });
        }

        for (const col of cols) {
            if (SNAKE_CASE_RE.test(col.name)) snakeOkCols += 1;
            else {
                rawFindings.push({
                    id: `${tableName}.${col.name}-naming`,
                    ruleCode: 'DDL_COLUMN_NAMING',
                    severity: 'P2',
                    category: '命名规范',
                    target: `${tableName}.${col.name}`,
                    message: `Column "${col.name}" is not lowercase snake_case.`,
                });
            }

            if (!col.hasInlineComment) {
                rawFindings.push({
                    id: `${tableName}.${col.name}-comment`,
                    ruleCode: 'DDL_MISSING_COLUMN_COMMENT',
                    severity: 'P1',
                    category: '注释覆盖',
                    target: `${tableName}.${col.name}`,
                    message: `Column "${tableName}.${col.name}" is missing a COMMENT.`,
                });
            }
            if (MONEY_NAME_RE.test(toSnakeLike(col.name)) && FLOAT_TYPE_RE.test(col.rawType)) {
                totalTypeIssues += 1;
                rawFindings.push({
                    id: `${tableName}.${col.name}-float-money`,
                    ruleCode: 'DDL_FLOAT_MONEY',
                    severity: 'P0',
                    category: '类型精度',
                    target: `${tableName}.${col.name}`,
                    message: `Monetary column "${col.name}" uses floating-point type "${col.rawType}". Use DECIMAL/NUMERIC.`,
                });
            } else if (normalizedDialect === 'mysql' && /^varchar$/i.test(col.rawType.trim())) {
                totalTypeIssues += 1;
                rawFindings.push({
                    id: `${tableName}.${col.name}-varchar-len`,
                    ruleCode: 'DDL_MYSQL_VARCHAR_LEN',
                    severity: 'P1',
                    category: '类型精度',
                    target: `${tableName}.${col.name}`,
                    message: `MySQL VARCHAR column "${col.name}" is missing explicit length.`,
                });
            }
        }

        tables.push({
            schema: pt.schema,
            name: tableName,
            columnCount: cols.length,
            hasPrimaryKey: hasPk,
            inheritedLike: pt.inheritedLike,
            hasTableComment,
            commentedColumns: commentedCount,
            hasAuditTimestamp,
        });
    }

    for (const af of alterAnalysis.findings) {
        rawFindings.push(af);
    }

    const findings = applyRuleConfig(rawFindings, config);
    const severityRank = { P0: 0, P1: 1, P2: 2 };
    findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

    const lockFindings = findings.filter((f) => f.category === '锁表风险');
    const lockPenalty =
        lockFindings.filter((f) => f.severity === 'P0').length * 25 +
        lockFindings.filter((f) => f.severity === 'P1').length * 10 +
        lockFindings.filter((f) => f.severity === 'P2').length * 5;

    let dimensions;
    let baseScore;
    let totalScore;

    if (tables.length > 0) {
        const safeCols = Math.max(totalCols, 1);
        const safeTables = Math.max(tables.length, 1);
        const namingScore = Math.round(((snakeOkCols + tables.filter((t) => SNAKE_CASE_RE.test(t.name)).length) / (safeCols + safeTables)) * 100);
        const commentScore = Math.round(((totalCommentedCols + tables.filter((t) => t.hasTableComment).length) / (safeCols + safeTables)) * 100);
        const pkScore = Math.round((tables.filter((t) => t.hasPrimaryKey).length / safeTables) * 100);
        const monitoringScore = Math.round((tables.filter((t) => t.hasAuditTimestamp).length / safeTables) * 100);
        const typeScore = Math.max(0, Math.round(100 - (totalTypeIssues / safeCols) * 200));

        dimensions = [
            { key: 'naming', weightPct: 25, score: namingScore, weighted: Number((namingScore * 25) / 100) },
            { key: 'comments', weightPct: 20, score: commentScore, weighted: Number((commentScore * 20) / 100) },
            { key: 'primaryKey', weightPct: 20, score: pkScore, weighted: Number((pkScore * 20) / 100) },
            { key: 'monitoring', weightPct: 20, score: monitoringScore, weighted: Number((monitoringScore * 20) / 100) },
            { key: 'types', weightPct: 15, score: typeScore, weighted: Number((typeScore * 15) / 100) },
        ];
        // Exact integer arithmetic to match verifiable-core verifyRecompute with zero IEEE-754 drift
        const exactNumerator = dimensions.reduce((acc, d) => acc + d.score * d.weightPct, 0);
        baseScore = Math.round(exactNumerator / 100);
        totalScore = Math.max(0, baseScore - lockPenalty);
    } else {
        baseScore = 100;
        totalScore = Math.max(0, 100 - lockPenalty);
        dimensions = [
            { key: 'alterLockSafety', weightPct: 100, score: totalScore, weighted: totalScore },
        ];
    }

    return {
        ok: true,
        dialect: normalizedDialect,
        tableCount: tables.length,
        alterStatementCount: alterAnalysis.alterStatementCount,
        columnCount: totalCols,
        baseScore,
        lockPenalty,
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
