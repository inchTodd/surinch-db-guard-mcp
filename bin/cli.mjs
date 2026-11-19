#!/usr/bin/env node
import fs from 'node:fs';
import { analyzeDdlGovernance, reviewSqlReadonly, scanSensitiveMasking, buildReceipt } from '../src/index.mjs';

const args = process.argv.slice(2);
const command = args[0];

function getFlag(name, fallback) {
    const idx = args.indexOf(name);
    return idx >= 0 && args[idx + 1] ? args[idx + 1] : fallback;
}

if (!command || command === '--help' || command === '-h') {
    console.log(`Usage:
  surinch-db-guard ddl-check [--dialect mysql|postgresql|doris] [--file path] [--receipt]
  surinch-db-guard sql-review [--dialect mysql|postgresql] [--file path] [--receipt]
  surinch-db-guard mask-scan [--dialect mysql|postgresql|doris] [--view-prefix v_masked_] [--file path] [--receipt]`);
    process.exit(0);
}

const filePath = getFlag('--file', '');
const dialect = getFlag('--dialect', 'mysql');
const viewPrefix = getFlag('--view-prefix', 'v_masked_');
const withReceipt = args.includes('--receipt');
const rawInput = filePath ? fs.readFileSync(filePath, 'utf8') : fs.readFileSync(0, 'utf8');

let result;
let toolName;
if (command === 'ddl-check') {
    toolName = 'ddl_governance_check';
    result = analyzeDdlGovernance(rawInput, dialect);
} else if (command === 'sql-review') {
    toolName = 'sql_readonly_review';
    result = reviewSqlReadonly(rawInput, dialect);
} else if (command === 'mask-scan') {
    toolName = 'sensitive_masking_scan';
    result = scanSensitiveMasking(rawInput, dialect, { viewPrefix });
} else {
    console.error(`Unknown command: ${command}`);
    process.exit(2);
}

const output = withReceipt ? { result, receipt: buildReceipt({ tool: toolName, rawInput, result }) } : result;
console.log(JSON.stringify(output, null, 2));

if (!result.ok) process.exit(2);
if (result.counts?.p0 > 0 || result.readonlySafe === false) process.exit(1);
process.exit(0);
