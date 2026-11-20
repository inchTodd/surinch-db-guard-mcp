import { SUPPORTED_DDL_DIALECTS, parseDdlTables } from './ddl-parser.mjs';
import { isRuleDisabled, resolveConfig, resolveRuleSeverity } from './config.mjs';

const VIEW_PREFIX_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

const SENSITIVE_RULES = [
    {
        category: 'CREDENTIAL_SECRET',
        level: 'L4',
        severity: 'P0',
        strategy: 'REDACT_NULL',
        nameRe: /(?:^|_)(password|passwd|pwd|password_hash|secret|secret_key|api_key|api_secret|api_secret_key|access_token|refresh_token|auth_token|session_token|private_key|client_secret)(?:$|_)/i,
        rationale: 'Credential or secret column must never be exposed in analytics or BI views.',
    },
    {
        category: 'NATIONAL_ID',
        level: 'L3',
        severity: 'P1',
        strategy: 'MASK_KEEP_3_4',
        nameRe: /(?:^|_)(id_card|id_card_no|id_no|identity_no|identity_card|national_id|ssn|social_security|passport|passport_no|driver_license)(?:$|_)/i,
        rationale: 'Government-issued identifier requires strong masking (keep prefix/suffix only).',
    },
    {
        category: 'BANK_FINANCIAL',
        level: 'L3',
        severity: 'P1',
        strategy: 'MASK_LAST_4',
        nameRe: /(?:^|_)(bank_card|bank_card_no|bank_card_number|bank_account|bank_acct|credit_card|debit_card|card_no|card_number|iban|cvv|cvc)(?:$|_)/i,
        rationale: 'Financial account or payment card number requires masking (keep last 4 digits).',
    },
    {
        category: 'MOBILE_PHONE',
        level: 'L3',
        severity: 'P1',
        strategy: 'MASK_KEEP_3_4',
        nameRe: /(?:^|_)(mobile|mobile_phone|mobile_no|phone|phone_no|phone_number|tel|telephone|cellphone|contact_phone)(?:$|_)/i,
        rationale: 'Personal telephone/mobile number requires masking (keep first 3 and last 4 digits).',
    },
    {
        category: 'EMAIL',
        level: 'L2',
        severity: 'P2',
        strategy: 'MASK_EMAIL',
        nameRe: /(?:^|_)(email|email_address|mail|contact_email)(?:$|_)/i,
        rationale: 'Email address should mask local-part while preserving domain for analytics.',
    },
    {
        category: 'PERSON_NAME',
        level: 'L2',
        severity: 'P2',
        strategy: 'MASK_FIRST_CHAR',
        nameRe: /(?:^|_)(full_name|real_name|true_name|legal_name|customer_name|user_name|contact_name|cardholder_name|recipient_name)(?:$|_)/i,
        rationale: 'Personal real name should retain only initial character.',
    },
    {
        category: 'IP_DEVICE',
        level: 'L2',
        severity: 'P2',
        strategy: 'MASK_FIRST_CHAR',
        nameRe: /(?:^|_)(ip_address|client_ip|login_ip|remote_ip|mac_address|imei|idfa|oaid|device_id)(?:$|_)/i,
        rationale: 'Network/device identifier should be masked or pseudonymized.',
    },
    {
        category: 'ADDRESS',
        level: 'L2',
        severity: 'P2',
        strategy: 'MASK_KEEP_6',
        nameRe: /(?:^|_)(home_address|street_address|detail_address|shipping_address|mailing_address|residential_address|address)(?:$|_)/i,
        rationale: 'Physical address should be generalized to coarse prefix.',
    },
];

function quoteIdent(name, dialect) {
    if (dialect === 'postgresql') return `"${String(name).replace(/"/g, '""')}"`;
    return `\`${String(name).replace(/`/g, '``')}\``;
}

function buildMaskExpr(colName, strategy, dialect) {
    const q = quoteIdent(colName, dialect);
    if (dialect === 'postgresql') {
        const s = `CAST(${q} AS TEXT)`;
        switch (strategy) {
            case 'REDACT_NULL':
                return `CAST(NULL AS TEXT) AS ${q}`;
            case 'MASK_KEEP_3_4':
                return `CASE WHEN ${q} IS NULL THEN NULL ELSE LEFT(${s}, 3) || '****' || RIGHT(${s}, 4) END AS ${q}`;
            case 'MASK_LAST_4':
                return `CASE WHEN ${q} IS NULL THEN NULL ELSE '****' || RIGHT(${s}, 4) END AS ${q}`;
            case 'MASK_EMAIL':
                return `CASE WHEN ${q} IS NULL THEN NULL ELSE LEFT(${s}, 1) || '***@' || SPLIT_PART(${s}, '@', 2) END AS ${q}`;
            case 'MASK_KEEP_6':
                return `CASE WHEN ${q} IS NULL THEN NULL ELSE LEFT(${s}, 6) || '***' END AS ${q}`;
            case 'MASK_FIRST_CHAR':
            default:
                return `CASE WHEN ${q} IS NULL THEN NULL ELSE LEFT(${s}, 1) || '***' END AS ${q}`;
        }
    }

    // MySQL / Apache Doris
    const s = `CAST(${q} AS CHAR)`;
    switch (strategy) {
        case 'REDACT_NULL':
            return `CAST(NULL AS CHAR(1)) AS ${q}`;
        case 'MASK_KEEP_3_4':
            return `CASE WHEN ${q} IS NULL THEN NULL ELSE CONCAT(LEFT(${s}, 3), '****', RIGHT(${s}, 4)) END AS ${q}`;
        case 'MASK_LAST_4':
            return `CASE WHEN ${q} IS NULL THEN NULL ELSE CONCAT('****', RIGHT(${s}, 4)) END AS ${q}`;
        case 'MASK_EMAIL':
            return `CASE WHEN ${q} IS NULL THEN NULL ELSE CONCAT(LEFT(${s}, 1), '***@', SUBSTRING_INDEX(${s}, '@', -1)) END AS ${q}`;
        case 'MASK_KEEP_6':
            return `CASE WHEN ${q} IS NULL THEN NULL ELSE CONCAT(LEFT(${s}, 6), '***') END AS ${q}`;
        case 'MASK_FIRST_CHAR':
        default:
            return `CASE WHEN ${q} IS NULL THEN NULL ELSE CONCAT(LEFT(${s}, 1), '***') END AS ${q}`;
    }
}

export function scanSensitiveMasking(rawSql, dialect = 'mysql', options = {}) {
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

    const viewPrefix = options.viewPrefix == null ? 'v_masked_' : String(options.viewPrefix).trim();
    if (!VIEW_PREFIX_RE.test(viewPrefix)) {
        return {
            ok: false,
            errorCode: 'INVALID_VIEW_PREFIX',
            message: `Invalid viewPrefix "${viewPrefix}". Must match /^[a-zA-Z_][a-zA-Z0-9_]*$/.`,
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

    const allRules = [
        ...(config.customSensitivePatterns || []),
        ...SENSITIVE_RULES,
    ];

    const findings = [];
    const tables = [];
    const maskingViews = [];
    let totalCols = 0;

    for (const pt of parsedTables) {
        totalCols += pt.columns.length;
        const matchedCols = new Map();
        const tableSensitive = [];

        for (const col of pt.columns) {
            const rule = allRules.find((r) => {
                if (!r.nameRe.test(col.name)) return false;
                const candidate = {
                    id: `${pt.name}.${col.name}-${r.category.toLowerCase().replace(/[^a-z0-9_]+/g, '_')}`,
                    ruleCode: r.ruleCode || r.category,
                    category: r.category,
                };
                return !isRuleDisabled(candidate, config);
            });
            if (rule) {
                const ruleCode = rule.ruleCode || rule.category;
                const id = `${pt.name}.${col.name}-${rule.category.toLowerCase().replace(/[^a-z0-9_]+/g, '_')}`;
                const baseItem = {
                    id,
                    ruleCode,
                    table: pt.name,
                    column: col.name,
                    rawType: col.rawType,
                    category: rule.category,
                    level: rule.level,
                    severity: rule.severity,
                    strategy: rule.strategy,
                    message: `Sensitive ${rule.level} (${rule.category}) column "${pt.name}.${col.name}": ${rule.rationale}`,
                };
                if (rule.custom) baseItem.custom = true;
                const finalSeverity = resolveRuleSeverity(baseItem, config);
                const item = finalSeverity === baseItem.severity ? baseItem : { ...baseItem, severity: finalSeverity };

                matchedCols.set(col.name, rule);
                findings.push(item);
                tableSensitive.push({
                    column: col.name,
                    category: rule.category,
                    level: rule.level,
                    strategy: rule.strategy,
                });
            }
        }

        if (matchedCols.size > 0) {
            const viewName = `${viewPrefix}${pt.name}`;
            const selectExprs = pt.columns.map((col) => {
                const rule = matchedCols.get(col.name);
                return rule ? buildMaskExpr(col.name, rule.strategy, normalizedDialect) : quoteIdent(col.name, normalizedDialect);
            });
            const viewSql = [
                `CREATE OR REPLACE VIEW ${quoteIdent(viewName, normalizedDialect)} AS`,
                'SELECT',
                selectExprs.map((e) => `    ${e}`).join(',\n'),
                `FROM ${quoteIdent(pt.name, normalizedDialect)};`,
            ].join('\n');

            maskingViews.push({
                table: pt.name,
                viewName,
                maskedColumnCount: matchedCols.size,
                sql: viewSql,
            });
        }

        tables.push({
            name: pt.name,
            columnCount: pt.columns.length,
            sensitiveColumnCount: matchedCols.size,
            sensitiveColumns: tableSensitive,
        });
    }

    const severityRank = { P0: 0, P1: 1, P2: 2 };
    findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.id.localeCompare(b.id));

    const l4 = findings.filter((f) => f.level === 'L4').length;
    const l3 = findings.filter((f) => f.level === 'L3').length;
    const l2 = findings.filter((f) => f.level === 'L2').length;
    const p0 = findings.filter((f) => f.severity === 'P0').length;
    const p1 = findings.filter((f) => f.severity === 'P1').length;
    const p2 = findings.filter((f) => f.severity === 'P2').length;

    return {
        ok: true,
        dialect: normalizedDialect,
        metadataOnly: true,
        tableCount: tables.length,
        columnCount: totalCols,
        tables,
        findings,
        maskingViews,
        counts: {
            l4,
            l3,
            l2,
            totalSensitive: findings.length,
            p0,
            p1,
            p2,
        },
    };
}
