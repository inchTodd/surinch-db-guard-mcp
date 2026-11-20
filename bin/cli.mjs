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

function hasFlag(name) {
    return args.includes(name);
}

function getFlag(name, fallback) {
    const idx = args.indexOf(name);
    if (idx < 0) return fallback;
    const next = args[idx + 1];
    if (!next || next.startsWith('--')) return '';
    return next;
}

if (!command || command === '--help' || command === '-h') {
    console.log(`Usage:
  surinch-db-guard ddl-check [--dialect mysql|postgresql|doris] [--file path | --dir directory] [--config .surinchrc.json] [--receipt]
  surinch-db-guard sql-review [--dialect mysql|postgresql] [--file path | --dir directory] [--config .surinchrc.json] [--receipt]
  surinch-db-guard mask-scan [--dialect mysql|postgresql|doris] [--view-prefix v_masked_] [--file path | --dir directory] [--config .surinchrc.json] [--receipt]`);
    process.exit(0);
}

const VALID_COMMANDS = new Set(['ddl-check', 'sql-review', 'mask-scan']);
if (!VALID_COMMANDS.has(command)) {
    console.error(`Unknown command: ${command}`);
    process.exit(2);
}

const filePath = getFlag('--file', '');
const dirPath = getFlag('--dir', '');
const hasDirFlag = hasFlag('--dir');
const hasConfigFlag = hasFlag('--config');
const configPath = getFlag('--config', '');
const dialect = getFlag('--dialect', 'mysql');
const viewPrefix = getFlag('--view-prefix', 'v_masked_');
const withReceipt = hasFlag('--receipt');

if (hasConfigFlag && !configPath) {
    const errResult = { ok: false, errorCode: 'INVALID_CONFIG', message: 'Missing path argument for --config.' };
    console.log(JSON.stringify(withReceipt || hasDirFlag ? { result: errResult, receipt: buildReceipt({ tool: command, rawInput: '', result: errResult }) } : errResult, null, 2));
    process.exit(2);
}

if (hasDirFlag) {
    const batch = scanDirectoryBatch({
        command,
        dirPath,
        dialect,
        viewPrefix,
        config: hasConfigFlag ? configPath : undefined,
    });
    console.log(JSON.stringify(batch, null, 2));
    if (!batch.result.ok) process.exit(2);
    if (batch.result.counts?.p0 > 0 || batch.result.readonlySafe === false || batch.receipt.verdict === 'BLOCK') process.exit(1);
    process.exit(0);
}

const rawInput = filePath ? fs.readFileSync(filePath, 'utf8') : fs.readFileSync(0, 'utf8');
const configOpt = hasConfigFlag ? configPath : undefined;

let result;
let toolName;
if (command === 'ddl-check') {
    toolName = 'ddl_governance_check';
    result = analyzeDdlGovernance(rawInput, dialect, { config: configOpt });
} else if (command === 'sql-review') {
    toolName = 'sql_readonly_review';
    result = reviewSqlReadonly(rawInput, dialect, { config: configOpt });
} else {
    toolName = 'sensitive_masking_scan';
    result = scanSensitiveMasking(rawInput, dialect, { viewPrefix, config: configOpt });
}

const output = withReceipt ? { result, receipt: buildReceipt({ tool: toolName, rawInput, result }) } : result;
console.log(JSON.stringify(output, null, 2));

if (!result.ok) process.exit(2);
if (result.counts?.p0 > 0 || result.readonlySafe === false) process.exit(1);
process.exit(0);
