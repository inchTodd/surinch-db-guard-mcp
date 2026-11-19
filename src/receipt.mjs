import crypto from 'node:crypto';

export const ENGINE_VERSION = '0.1.0';
export const RECEIPT_SCHEMA_VERSION = 'surinch.receipt.h1';

function canonicalize(value) {
    if (value === null || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map(canonicalize);
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
        sorted[key] = canonicalize(value[key]);
    }
    return sorted;
}

export function sha256Hex(text) {
    return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

export function buildReceipt({ tool, rawInput, result }) {
    const inputSha256 = sha256Hex(rawInput);
    const outputSha256 = sha256Hex(JSON.stringify(canonicalize(result)));
    let verdict = 'INVALID_INPUT';
    if (result?.ok) {
        if (result.counts?.p0 > 0 || result.readonlySafe === false) verdict = 'BLOCK';
        else if ((result.counts?.p1 || 0) + (result.counts?.p2 || 0) > 0) verdict = 'WARN';
        else verdict = 'PASS';
    }
    return {
        schema_version: RECEIPT_SCHEMA_VERSION,
        tool,
        engine_version: ENGINE_VERSION,
        verdict,
        input_sha256: inputSha256,
        output_sha256: outputSha256,
        generated_at: new Date().toISOString(),
    };
}
