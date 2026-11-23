#!/usr/bin/env node
import fs from 'node:fs';
import {
    analyzeDdlGovernance,
    reviewSqlReadonly,
    scanSensitiveMasking,
    scanDirectoryBatch,
    buildReceipt,
} from '../src/index.mjs';

const args = process.argv.slice(2);
const command = args[0];

const VALUE_FLAGS = new Set([
    '--dialect',
    '--file',
    '--dir',
    '--config',
    '--view-prefix',
    '--sql',
    '--db-version',
]);

const BOOL_FLAGS = new Set([
    '--receipt',
    '--replace-view',
    '--help',
    '-h',
]);

function parseArgs(argv) {
    const flags = new Map();
    const bools = new Set();
    const positionals = [];
    for (let i = 1; i < argv.length; i += 1) {
        const tok = argv[i];
        if (VALUE_FLAGS.has(tok)) {
            const next = argv[i + 1];
            if (next !== undefined && !next.startsWith('--')) {
                flags.set(tok, next);
                i += 1;
            } else {
                flags.set(tok, '');
            }
            continue;
        }
        if (BOOL_FLAGS.has(tok)) {
            bools.add(tok);
            continue;
        }
        if (tok.startsWith('-')) {
            return { ok: false, unknownFlag: tok };
        }
        positionals.push(tok);
    }
    return { ok: true, flags, bools, positionals };
}

if (!command || command === '--help' || command === '-h') {
    console.log(`Usage:
  surinch-db-guard ddl-check  [--dialect mysql|postgresql|doris] [--file <path> | --sql "<sql>" | <file> | --dir <directory>] [--config .surinchrc.json] [--receipt]
  surinch-db-guard sql-review [--dialect mysql|postgresql]       [--file <path> | --sql "<sql>" | <file> | --dir <directory>] [--config .surinchrc.json] [--receipt]
  surinch-db-guard mask-scan  [--dialect mysql|postgresql|doris] [--view-prefix v_masked_] [--replace-view] [--file <path> | --sql "<sql>" | <file> | --dir <directory>] [--config .surinchrc.json] [--receipt]

Input sources (in order of precedence):
  --sql "<text>"    Inline SQL/DDL string
  --file <path>     Path to a .sql file (or pass <file> as a positional argument)
  --dir <directory> Recursively scan all .sql files in a directory
  stdin             Piped SQL/DDL (e.g., cat schema.sql | surinch-db-guard ddl-check)

Exit codes:
  0  PASS / WARN (no P0 blockers)
  1  BLOCK (P0 finding or readonly violation)
  2  INVALID_INPUT / CLI error`);
    process.exit(0);
}

const VALID_COMMANDS = new Set(['ddl-check', 'sql-review', 'mask-scan']);
if (!VALID_COMMANDS.has(command)) {
    console.error(`Unknown command: ${command}`);
    process.exit(2);
}

const parsed = parseArgs(args);
if (!parsed.ok) {
    const errResult = { ok: false, errorCode: 'UNKNOWN_FLAG', message: `Unknown flag: ${parsed.unknownFlag}` };
    console.log(JSON.stringify(errResult, null, 2));
    process.exit(2);
}

const { flags, bools, positionals } = parsed;
const hasSqlFlag = flags.has('--sql');
const inlineSql = flags.get('--sql') ?? '';
const filePath = flags.get('--file') || (!hasSqlFlag && positionals[0] ? positionals[0] : '');
const hasDirFlag = flags.has('--dir');
const dirPath = flags.get('--dir') || '';
const hasConfigFlag = flags.has('--config');
const configPath = flags.get('--config') || '';
const dialect = flags.get('--dialect') || 'mysql';
const viewPrefix = flags.get('--view-prefix') || 'v_masked_';
const dbVersion = flags.get('--db-version') || undefined;
const withReceipt = bools.has('--receipt');
const replaceView = bools.has('--replace-view');

const TOOL_MAP = {
    'ddl-check': 'ddl_governance_check',
    'sql-review': 'sql_readonly_review',
    'mask-scan': 'sensitive_masking_scan',
};
const toolName = TOOL_MAP[command];

if (hasConfigFlag && !configPath) {
    const errResult = { ok: false, errorCode: 'INVALID_CONFIG', message: 'Missing path argument for --config.' };
    console.log(JSON.stringify(withReceipt || hasDirFlag ? { result: errResult, receipt: buildReceipt({ tool: toolName, rawInput: '', result: errResult, dialect }) } : errResult, null, 2));
    process.exit(2);
}

if (hasDirFlag) {
    const batch = scanDirectoryBatch({
        command,
        dirPath,
        dialect,
        viewPrefix,
        replaceView,
        config: hasConfigFlag ? configPath : undefined,
    });
    console.log(JSON.stringify(batch, null, 2));
    if (!batch.result.ok) process.exit(2);
    if (batch.result.counts?.p0 > 0 || batch.result.readonlySafe === false || batch.receipt.verdict === 'BLOCK') process.exit(1);
    process.exit(0);
}

let rawInput = '';
if (hasSqlFlag) {
    rawInput = inlineSql;
} else if (filePath) {
    try {
        rawInput = fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        const errResult = { ok: false, errorCode: 'FILE_READ_ERROR', message: `Failed to read input file "${filePath}": ${err.message}` };
        console.log(JSON.stringify(withReceipt ? { result: errResult, receipt: buildReceipt({ tool: toolName, rawInput: '', result: errResult, dialect }) } : errResult, null, 2));
        process.exit(2);
    }
} else if (process.stdin.isTTY) {
    const errResult = {
        ok: false,
        errorCode: 'EMPTY_INPUT',
        message: 'No input provided. Pass --sql "<sql>", --file <path>, a positional file path, --dir <dir>, or pipe SQL via stdin.',
    };
    console.log(JSON.stringify(withReceipt ? { result: errResult, receipt: buildReceipt({ tool: toolName, rawInput: '', result: errResult, dialect }) } : errResult, null, 2));
    process.exit(2);
} else {
    rawInput = fs.readFileSync(0, 'utf8');
}

const configOpt = hasConfigFlag ? configPath : undefined;

let result;
if (command === 'ddl-check') {
    result = analyzeDdlGovernance(rawInput, dialect, { config: configOpt, dbVersion });
} else if (command === 'sql-review') {
    result = reviewSqlReadonly(rawInput, dialect, { config: configOpt, dbVersion });
} else {
    result = scanSensitiveMasking(rawInput, dialect, { viewPrefix, replaceView, config: configOpt });
}

const output = withReceipt
    ? { result, receipt: buildReceipt({ tool: toolName, rawInput, result, dialect, config: configOpt }) }
    : result;
console.log(JSON.stringify(output, null, 2));

if (!result.ok) process.exit(2);
if (result.counts?.p0 > 0 || result.readonlySafe === false) process.exit(1);
process.exit(0);
