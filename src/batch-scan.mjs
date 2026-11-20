import fs from 'node:fs';
import path from 'node:path';
import { analyzeDdlGovernance } from './ddl-check.mjs';
import { reviewSqlReadonly } from './sql-review.mjs';
import { scanSensitiveMasking } from './sensitive-masking.mjs';
import { resolveConfig } from './config.mjs';
import { buildReceipt } from './receipt.mjs';

const TOOL_MAP = {
    'ddl-check': 'ddl_governance_check',
    'sql-review': 'sql_readonly_review',
    'mask-scan': 'sensitive_masking_scan',
};

const SKIP_DIRS = new Set(['.git', 'node_modules']);

function collectSqlFiles(rootDir, currentDir = rootDir, acc = []) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
            if (SKIP_DIRS.has(entry.name)) continue;
            collectSqlFiles(rootDir, fullPath, acc);
        } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.sql')) {
            const relPath = path.relative(rootDir, fullPath).split(path.sep).join('/');
            acc.push({ relPath, fullPath });
        }
    }
    return acc;
}

function computeFileVerdict(res) {
    if (!res?.ok) return 'INVALID_INPUT';
    if ((res.counts?.p0 || 0) > 0 || res.readonlySafe === false) return 'BLOCK';
    if ((res.counts?.p1 || 0) + (res.counts?.p2 || 0) > 0) return 'WARN';
    return 'PASS';
}

export function scanDirectoryBatch({ command, dirPath, dialect = 'mysql', viewPrefix = 'v_masked_', config }) {
    const toolName = TOOL_MAP[command];
    if (!toolName) {
        const result = {
            ok: false,
            errorCode: 'UNKNOWN_COMMAND',
            message: `Unknown command "${command}". Supported: ddl-check, sql-review, mask-scan.`,
        };
        return { result, receipt: buildReceipt({ tool: 'batch_scan', rawInput: '', result }) };
    }

    const cfgRes = resolveConfig(config);
    if (!cfgRes.ok) {
        return { result: cfgRes, receipt: buildReceipt({ tool: toolName, rawInput: '', result: cfgRes }) };
    }
    const resolvedConfig = cfgRes.config;

    if (!dirPath || typeof dirPath !== 'string' || !dirPath.trim()) {
        const result = { ok: false, errorCode: 'INVALID_DIR', message: 'Directory path is empty.' };
        return { result, receipt: buildReceipt({ tool: toolName, rawInput: '', result }) };
    }

    let stat;
    try {
        stat = fs.statSync(dirPath);
    } catch (err) {
        const result = { ok: false, errorCode: 'INVALID_DIR', message: `Directory not found: "${dirPath}" (${err.message}).` };
        return { result, receipt: buildReceipt({ tool: toolName, rawInput: '', result }) };
    }
    if (!stat.isDirectory()) {
        const result = { ok: false, errorCode: 'INVALID_DIR', message: `Path is not a directory: "${dirPath}".` };
        return { result, receipt: buildReceipt({ tool: toolName, rawInput: '', result }) };
    }

    const discovered = collectSqlFiles(dirPath);
    discovered.sort((a, b) => (a.relPath < b.relPath ? -1 : a.relPath > b.relPath ? 1 : 0));

    if (discovered.length === 0) {
        const result = {
            ok: false,
            errorCode: 'EMPTY_DIR',
            message: `No .sql files found in directory "${dirPath}".`,
        };
        return { result, receipt: buildReceipt({ tool: toolName, rawInput: '', result }) };
    }

    const perFileResults = [];
    const canonicalChunks = [];
    let passedFiles = 0;
    let warnedFiles = 0;
    let blockedFiles = 0;
    let invalidFiles = 0;
    let totalP0 = 0;
    let totalP1 = 0;
    let totalP2 = 0;
    let allReadonlySafe = true;

    for (const item of discovered) {
        const content = fs.readFileSync(item.fullPath, 'utf8');
        canonicalChunks.push(`--- ${item.relPath} ---\n${content}`);

        let fileResult;
        if (command === 'ddl-check') {
            fileResult = analyzeDdlGovernance(content, dialect, { config: resolvedConfig });
        } else if (command === 'sql-review') {
            fileResult = reviewSqlReadonly(content, dialect, { config: resolvedConfig });
        } else {
            fileResult = scanSensitiveMasking(content, dialect, { viewPrefix, config: resolvedConfig });
        }

        const verdict = computeFileVerdict(fileResult);
        if (verdict === 'PASS') passedFiles += 1;
        else if (verdict === 'WARN') warnedFiles += 1;
        else if (verdict === 'BLOCK') blockedFiles += 1;
        else invalidFiles += 1;

        if (fileResult?.ok) {
            totalP0 += fileResult.counts?.p0 || 0;
            totalP1 += fileResult.counts?.p1 || 0;
            totalP2 += fileResult.counts?.p2 || 0;
            if (fileResult.readonlySafe === false) allReadonlySafe = false;
        } else {
            allReadonlySafe = false;
        }

        perFileResults.push({
            file: item.relPath,
            verdict,
            result: fileResult,
        });
    }

    const aggregateResult = {
        ok: invalidFiles === 0,
        mode: 'batch',
        tool: toolName,
        dialect: String(dialect || '').trim().toLowerCase(),
        fileCount: discovered.length,
        ...(command === 'sql-review' ? { readonlySafe: allReadonlySafe && totalP0 === 0 } : {}),
        ...(invalidFiles > 0 ? { errorCode: 'BATCH_CONTAINS_INVALID_FILES', message: `${invalidFiles} file(s) failed validation.` } : {}),
        summary: {
            totalFiles: discovered.length,
            passedFiles,
            warnedFiles,
            blockedFiles,
            invalidFiles,
            counts: { p0: totalP0, p1: totalP1, p2: totalP2 },
        },
        counts: { p0: totalP0, p1: totalP1, p2: totalP2 },
        files: perFileResults,
    };

    const rawInput = canonicalChunks.join('\n');
    const receipt = buildReceipt({ tool: toolName, rawInput, result: aggregateResult });

    return { result: aggregateResult, receipt };
}
