#!/usr/bin/env node
import fs from 'node:fs';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import {
    analyzeDdlGovernance,
    reviewSqlReadonly,
    scanSensitiveMasking,
    buildReceipt,
    ENGINE_VERSION,
} from '../src/index.mjs';

const CONFIG_SCHEMA = {
    type: 'object',
    description: 'Optional enterprise rule config (.surinchrc.json object): disabledRules, severityOverrides, customSensitivePatterns. File paths are forbidden over MCP.',
    properties: {
        disabledRules: { type: 'array', items: { type: 'string' } },
        severityOverrides: { type: 'object', additionalProperties: { type: 'string', enum: ['P0', 'P1', 'P2'] } },
        customSensitivePatterns: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    level: { type: 'string', enum: ['L4', 'L3', 'L2'] },
                    pattern: { type: 'string' },
                    label: { type: 'string' },
                },
                required: ['level', 'pattern', 'label'],
            },
        },
    },
};

const TOOLS = [
    {
        name: 'ddl_governance_check',
        description: 'Score CREATE TABLE / ALTER TABLE DDL (MySQL/PostgreSQL/Doris) across 5 weighted governance dimensions plus ALTER TABLE lock-risk detection, with SHA-256 verifiable receipt. Rejects empty/invalid input, unparsed statements, invalid config, or unsupported dialect.',
        inputSchema: {
            type: 'object',
            properties: {
                ddl: { type: 'string', description: 'Sanitized CREATE TABLE / ALTER TABLE DDL text (no production credentials or row data).' },
                dialect: { type: 'string', enum: ['mysql', 'postgresql', 'doris'], default: 'mysql' },
                config: CONFIG_SCHEMA,
            },
            required: ['ddl'],
        },
    },
    {
        name: 'sql_readonly_review',
        description: 'Allowlist-first static readonly safety gate, ALTER TABLE lock-risk detector, and anti-pattern reviewer for MySQL/PostgreSQL SQL with SHA-256 verifiable receipt. Blocks non-readonly statements, DO blocks, data-modifying CTEs, SELECT INTO, side-effect functions, and EXPLAIN ANALYZE.',
        inputSchema: {
            type: 'object',
            properties: {
                sql: { type: 'string', description: 'SQL statement(s) to review.' },
                dialect: { type: 'string', enum: ['mysql', 'postgresql'], default: 'postgresql' },
                config: CONFIG_SCHEMA,
            },
            required: ['sql'],
        },
    },
    {
        name: 'sensitive_masking_scan',
        description: 'Metadata-only sensitive column classifier (L4/L3/L2 + custom enterprise patterns) & schema-aware masking VIEW SQL generator for MySQL/PostgreSQL/Doris DDL with SHA-256 verifiable receipt. Never reads row data.',
        inputSchema: {
            type: 'object',
            properties: {
                ddl: { type: 'string', description: 'CREATE TABLE DDL metadata text (schema-only, no sample row values).' },
                dialect: { type: 'string', enum: ['mysql', 'postgresql', 'doris'], default: 'mysql' },
                viewPrefix: { type: 'string', default: 'v_masked_', description: 'Prefix for generated masking VIEW names (alphanumeric + underscore).' },
                replaceView: { type: 'boolean', default: false, description: 'Emit CREATE OR REPLACE VIEW instead of safe default CREATE VIEW.' },
                config: CONFIG_SCHEMA,
            },
            required: ['ddl'],
        },
    },
];

function send(msg) {
    process.stdout.write(`${JSON.stringify(msg)}\n`);
}

function validateMcpConfigArg(configArg) {
    if (configArg === undefined || configArg === null) return { ok: true, config: undefined };
    // Security (C4): Never allow MCP callers to pass local filesystem paths to config
    if (typeof configArg !== 'object' || Array.isArray(configArg)) {
        return {
            ok: false,
            errorCode: 'INVALID_CONFIG',
            message: 'MCP "config" argument must be an inline JSON object; file path strings are not allowed over MCP.',
        };
    }
    return { ok: true, config: configArg };
}

export function handleJsonRpcRequest(req) {
    const { id, method, params } = req || {};

    // JSON-RPC 2.0 & MCP notifications MUST NOT receive a response
    if (id === undefined || (typeof method === 'string' && method.startsWith('notifications/'))) {
        return null;
    }

    if (method === 'ping') {
        return { jsonrpc: '2.0', id, result: {} };
    }

    if (method === 'initialize') {
        return {
            jsonrpc: '2.0',
            id,
            result: {
                protocolVersion: '2024-11-05',
                capabilities: { tools: {} },
                serverInfo: { name: '@surinch/db-guard-mcp', version: ENGINE_VERSION },
            },
        };
    }

    if (method === 'tools/list') {
        return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
    }

    if (method === 'tools/call') {
        const name = params?.name;
        const toolArgs = params?.arguments || {};

        const mcpCfg = validateMcpConfigArg(toolArgs.config);
        if (!mcpCfg.ok) {
            const rawInput = String(toolArgs.ddl ?? toolArgs.sql ?? '');
            const dialect = toolArgs.dialect ?? (name === 'sql_readonly_review' ? 'postgresql' : 'mysql');
            const payload = {
                result: mcpCfg,
                receipt: buildReceipt({ tool: name || 'unknown', rawInput, result: mcpCfg, dialect }),
            };
            return {
                jsonrpc: '2.0',
                id,
                result: { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], isError: true },
            };
        }

        if (name === 'ddl_governance_check') {
            const rawInput = String(toolArgs.ddl ?? '');
            const dialect = toolArgs.dialect ?? 'mysql';
            const result = analyzeDdlGovernance(rawInput, dialect, {
                config: mcpCfg.config,
            });
            const payload = { result, receipt: buildReceipt({ tool: name, rawInput, result, dialect, config: mcpCfg.config }) };
            return {
                jsonrpc: '2.0',
                id,
                result: { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], isError: !result.ok },
            };
        }
        if (name === 'sql_readonly_review') {
            const rawInput = String(toolArgs.sql ?? '');
            const dialect = toolArgs.dialect ?? 'postgresql';
            const result = reviewSqlReadonly(rawInput, dialect, {
                config: mcpCfg.config,
            });
            const payload = { result, receipt: buildReceipt({ tool: name, rawInput, result, dialect, config: mcpCfg.config }) };
            return {
                jsonrpc: '2.0',
                id,
                result: { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], isError: !result.ok },
            };
        }
        if (name === 'sensitive_masking_scan') {
            const rawInput = String(toolArgs.ddl ?? '');
            const dialect = toolArgs.dialect ?? 'mysql';
            const result = scanSensitiveMasking(rawInput, dialect, {
                viewPrefix: toolArgs.viewPrefix,
                replaceView: toolArgs.replaceView,
                config: mcpCfg.config,
            });
            const payload = { result, receipt: buildReceipt({ tool: name, rawInput, result, dialect, config: mcpCfg.config }) };
            return {
                jsonrpc: '2.0',
                id,
                result: { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }], isError: !result.ok },
            };
        }
        return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } };
    }
    return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

function isMainModule() {
    if (!process.argv[1]) return false;
    try {
        return fs.realpathSync(fileURLToPath(import.meta.url)) === fs.realpathSync(process.argv[1]);
    } catch {
        return import.meta.url === `file://${process.argv[1]}`;
    }
}

if (isMainModule()) {
    const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
    rl.on('line', (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        try {
            const req = JSON.parse(trimmed);
            const res = handleJsonRpcRequest(req);
            if (res) send(res);
        } catch (err) {
            send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: `Parse error: ${err.message}` } });
        }
    });
}
