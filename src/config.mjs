import fs from 'node:fs';

const VALID_SEVERITIES = new Set(['P0', 'P1', 'P2']);
const VALID_LEVELS = new Set(['L4', 'L3', 'L2']);
const VALID_STRATEGIES = new Set([
    'REDACT_NULL',
    'MASK_KEEP_3_4',
    'MASK_LAST_4',
    'MASK_EMAIL',
    'MASK_KEEP_6',
    'MASK_FIRST_CHAR',
]);

const LEVEL_DEFAULT_SEVERITY = {
    L4: 'P0',
    L3: 'P1',
    L2: 'P2',
};

const LEVEL_DEFAULT_STRATEGY = {
    L4: 'REDACT_NULL',
    L3: 'MASK_KEEP_3_4',
    L2: 'MASK_FIRST_CHAR',
};

export const EMPTY_CONFIG = Object.freeze({
    disabledRules: new Set(),
    severityOverrides: Object.freeze({}),
    customSensitivePatterns: Object.freeze([]),
});

function invalidConfig(message) {
    return {
        ok: false,
        errorCode: 'INVALID_CONFIG',
        message,
    };
}

function isPlainObject(val) {
    return val !== null && typeof val === 'object' && !Array.isArray(val);
}

export function validateConfig(rawConfig) {
    if (!isPlainObject(rawConfig)) {
        return invalidConfig('Configuration must be a JSON object.');
    }

    const disabledRules = new Set();
    if (rawConfig.disabledRules !== undefined) {
        if (!Array.isArray(rawConfig.disabledRules)) {
            return invalidConfig('"disabledRules" must be an array of rule IDs/codes.');
        }
        for (let i = 0; i < rawConfig.disabledRules.length; i += 1) {
            const rule = rawConfig.disabledRules[i];
            if (typeof rule !== 'string' || !rule.trim()) {
                return invalidConfig(`"disabledRules[${i}]" must be a non-empty string.`);
            }
            disabledRules.add(rule.trim());
        }
    }

    const severityOverrides = {};
    if (rawConfig.severityOverrides !== undefined) {
        if (!isPlainObject(rawConfig.severityOverrides)) {
            return invalidConfig('"severityOverrides" must be an object mapping ruleId to "P0" | "P1" | "P2".');
        }
        for (const [ruleId, sev] of Object.entries(rawConfig.severityOverrides)) {
            if (!ruleId.trim()) {
                return invalidConfig('"severityOverrides" contains an empty rule key.');
            }
            if (typeof sev !== 'string' || !VALID_SEVERITIES.has(sev)) {
                return invalidConfig(
                    `Invalid severity "${String(sev)}" for rule "${ruleId}". Allowed values: P0, P1, P2.`
                );
            }
            severityOverrides[ruleId.trim()] = sev;
        }
    }

    const customSensitivePatterns = [];
    if (rawConfig.customSensitivePatterns !== undefined) {
        if (!Array.isArray(rawConfig.customSensitivePatterns)) {
            return invalidConfig('"customSensitivePatterns" must be an array of pattern objects.');
        }
        for (let i = 0; i < rawConfig.customSensitivePatterns.length; i += 1) {
            const entry = rawConfig.customSensitivePatterns[i];
            if (!isPlainObject(entry)) {
                return invalidConfig(`"customSensitivePatterns[${i}]" must be an object.`);
            }
            if (typeof entry.level !== 'string' || !VALID_LEVELS.has(entry.level)) {
                return invalidConfig(
                    `Invalid level "${String(entry.level)}" in customSensitivePatterns[${i}]. Allowed values: L4, L3, L2.`
                );
            }
            if (typeof entry.pattern !== 'string' || !entry.pattern.trim()) {
                return invalidConfig(`"customSensitivePatterns[${i}].pattern" must be a non-empty regex string.`);
            }
            if (typeof entry.label !== 'string' || !entry.label.trim()) {
                return invalidConfig(`"customSensitivePatterns[${i}].label" must be a non-empty string.`);
            }
            if (entry.strategy !== undefined && (typeof entry.strategy !== 'string' || !VALID_STRATEGIES.has(entry.strategy))) {
                return invalidConfig(
                    `Invalid strategy "${String(entry.strategy)}" in customSensitivePatterns[${i}].`
                );
            }
            let nameRe;
            try {
                nameRe = new RegExp(entry.pattern, 'i');
            } catch (err) {
                return invalidConfig(
                    `Invalid regex pattern "${entry.pattern}" in customSensitivePatterns[${i}]: ${err.message}`
                );
            }
            const label = entry.label.trim();
            customSensitivePatterns.push({
                category: label,
                ruleCode: label,
                level: entry.level,
                severity: LEVEL_DEFAULT_SEVERITY[entry.level],
                strategy: entry.strategy || LEVEL_DEFAULT_STRATEGY[entry.level],
                pattern: entry.pattern,
                nameRe,
                rationale: `Custom sensitive rule (${label}).`,
                custom: true,
            });
        }
    }

    return {
        ok: true,
        config: {
            disabledRules,
            severityOverrides,
            customSensitivePatterns,
        },
    };
}

export function loadConfigFile(filePath) {
    if (typeof filePath !== 'string' || !filePath.trim()) {
        return invalidConfig('Config file path must be a non-empty string.');
    }
    let rawText;
    try {
        rawText = fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        return invalidConfig(`Failed to read config file "${filePath}": ${err.message}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(rawText);
    } catch (err) {
        return invalidConfig(`Malformed JSON in config file "${filePath}": ${err.message}`);
    }
    return validateConfig(parsed);
}

export function resolveConfig(configInput) {
    if (configInput === undefined || configInput === null) {
        return { ok: true, config: EMPTY_CONFIG };
    }
    if (typeof configInput === 'string') {
        return loadConfigFile(configInput);
    }
    if (isPlainObject(configInput)) {
        // Already normalized config from a previous validateConfig call
        if (configInput.disabledRules instanceof Set && isPlainObject(configInput.severityOverrides) && Array.isArray(configInput.customSensitivePatterns)) {
            return { ok: true, config: configInput };
        }
        return validateConfig(configInput);
    }
    return invalidConfig('Config must be a file path string or a JSON configuration object.');
}

export function isRuleDisabled(finding, config) {
    if (!config || !config.disabledRules || config.disabledRules.size === 0) return false;
    const keys = [finding.ruleCode, finding.id, finding.category].filter(Boolean);
    return keys.some((k) => config.disabledRules.has(k));
}

export function resolveRuleSeverity(finding, config) {
    if (!config || !config.severityOverrides) return finding.severity;
    const keys = [finding.ruleCode, finding.id, finding.category].filter(Boolean);
    for (const k of keys) {
        if (Object.prototype.hasOwnProperty.call(config.severityOverrides, k)) {
            return config.severityOverrides[k];
        }
    }
    return finding.severity;
}

export function applyRuleConfig(findings, config) {
    if (!config) return findings;
    const result = [];
    for (const f of findings) {
        if (isRuleDisabled(f, config)) continue;
        const severity = resolveRuleSeverity(f, config);
        result.push(severity === f.severity ? f : { ...f, severity });
    }
    return result;
}
