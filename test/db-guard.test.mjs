import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
    analyzeDdlGovernance,
    reviewSqlReadonly,
    scanSensitiveMasking,
    buildReceipt,
} from '../src/index.mjs';
import { handleJsonRpcRequest } from '../bin/mcp-server.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, '..');
const FIXTURES_DIR = path.join(__dirname, 'fixtures');

function readFixture(name) {
    return fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf8');
}

test('DDL check rejects empty, comment-only, non-DDL, and unsupported dialect (no fake green)', () => {
    assert.equal(analyzeDdlGovernance('   ').errorCode, 'EMPTY_INPUT');
    assert.equal(analyzeDdlGovernance('-- only comment\n/* block */').errorCode, 'NO_CREATE_TABLE');
    assert.equal(analyzeDdlGovernance('SELECT 1;', 'mysql').errorCode, 'NO_CREATE_TABLE');
    assert.equal(analyzeDdlGovernance('CREATE TABLE t (id INT);', 'oracle').errorCode, 'UNSUPPORTED_DIALECT');

    const ok = analyzeDdlGovernance(`
        CREATE TABLE orders_fact (
            id BIGINT NOT NULL PRIMARY KEY COMMENT 'pk',
            pay_amount DECIMAL(18,2) NOT NULL COMMENT 'amount',
            created_at DATETIME NOT NULL COMMENT 'ts'
        ) COMMENT='orders';
    `, 'mysql');
    assert.equal(ok.ok, true);
    assert.equal(ok.totalScore, 100);
    assert.equal(ok.findings.length, 0);
});

test('SQL review handles positive, negative, and fault-injection cases cleanly', () => {
    assert.equal(reviewSqlReadonly('  ', 'postgresql').errorCode, 'EMPTY_INPUT');
    assert.equal(reviewSqlReadonly('-- comment only\n/* block */', 'postgresql').errorCode, 'NO_STATEMENT');
    assert.equal(reviewSqlReadonly('SELECT 1;', 'sqlite').errorCode, 'UNSUPPORTED_DIALECT');

    const safe = reviewSqlReadonly("SELECT id, REPLACE(name, 'a', 'b') FROM items WHERE status <> 'DROP';", 'mysql');
    assert.equal(safe.ok, true);
    assert.equal(safe.readonlySafe, true);
    assert.equal(safe.verdict, 'SAFE_READONLY');
    assert.equal(safe.findings.length, 0);

    const explainBlocked = reviewSqlReadonly('EXPLAIN (ANALYZE, BUFFERS) SELECT id FROM items;', 'postgresql');
    assert.equal(explainBlocked.ok, true);
    assert.equal(explainBlocked.readonlySafe, false);
    assert.equal(explainBlocked.findings[0].ruleCode, 'R01_EXPLAIN_ANALYZE');

    const deleteBlocked = reviewSqlReadonly('DELETE FROM items;', 'postgresql');
    assert.equal(deleteBlocked.ok, true);
    assert.equal(deleteBlocked.readonlySafe, false);
    assert.equal(deleteBlocked.counts.p0, 1);
    assert.equal(deleteBlocked.findings[0].ruleCode, 'R02_DML_NO_WHERE');
});

test('Real Docker pg_dump fixtures (PG 14 & PG 17) pass DDL governance regression', () => {
    for (const file of ['pg14-dump.sql', 'pg17-dump.sql']) {
        const dump = readFixture(file);
        const res = analyzeDdlGovernance(dump, 'postgresql');
        assert.equal(res.ok, true, `${file} should parse`);
        assert.equal(res.tableCount, 3, `${file} should have 3 tables`);

        const orders = res.tables.find((t) => t.name === 'orders_fact');
        assert.ok(orders, `${file} missing orders_fact`);
        assert.equal(orders.hasPrimaryKey, true, `${file} orders_fact PK via ALTER TABLE ONLY`);
        assert.equal(orders.hasTableComment, true, `${file} orders_fact table comment`);
        assert.equal(orders.commentedColumns, 4, `${file} orders_fact all 4 columns commented`);
        assert.equal(orders.hasAuditTimestamp, true);

        const legacy = res.tables.find((t) => t.name === 'LegacyAuditLog');
        assert.ok(legacy, `${file} missing LegacyAuditLog`);
        assert.equal(legacy.hasPrimaryKey, false);
        assert.equal(legacy.hasTableComment, false);

        // P0: missing PK on LegacyAuditLog + double precision total_amount
        assert.equal(res.counts.p0, 2, `${file} should report exactly 2 P0 findings`);
    }
});

test('Real Docker mysqldump fixtures (MySQL 8.0 & MySQL 8.4) pass DDL governance regression', () => {
    for (const file of ['mysql80-dump.sql', 'mysql84-dump.sql']) {
        const dump = readFixture(file);
        const res = analyzeDdlGovernance(dump, 'mysql');
        assert.equal(res.ok, true, `${file} should parse`);
        assert.equal(res.tableCount, 3, `${file} should have 3 tables`);

        const orders = res.tables.find((t) => t.name === 'orders_fact');
        assert.ok(orders);
        assert.equal(orders.hasPrimaryKey, true);
        assert.equal(orders.hasTableComment, true);
        assert.equal(orders.commentedColumns, 4);
        assert.equal(orders.hasAuditTimestamp, true);

        const bad = res.tables.find((t) => t.name === 'BadBillingLedger');
        assert.ok(bad);
        assert.equal(bad.hasPrimaryKey, false);
        assert.equal(bad.hasTableComment, false);

        // P0: missing PK on BadBillingLedger + float OrderAmt + double pay_amount
        assert.equal(res.counts.p0, 3, `${file} should report exactly 3 P0 findings`);
    }
});

test('sensitive_masking_scan classifies L4/L3/L2 metadata and generates dialect-safe VIEW SQL across 4 DB dumps', () => {
    // Fault injection / negative cases
    assert.equal(scanSensitiveMasking('', 'mysql').errorCode, 'EMPTY_INPUT');
    assert.equal(scanSensitiveMasking('-- comment', 'postgresql').errorCode, 'NO_CREATE_TABLE');
    assert.equal(scanSensitiveMasking('CREATE TABLE t (id INT);', 'oracle').errorCode, 'UNSUPPORTED_DIALECT');
    assert.equal(
        scanSensitiveMasking('CREATE TABLE t (phone VARCHAR(20));', 'mysql', { viewPrefix: 'v; DROP TABLE x;--' }).errorCode,
        'INVALID_VIEW_PREFIX'
    );

    // Clean non-sensitive table -> PASS with 0 views
    const clean = scanSensitiveMasking('CREATE TABLE metrics_daily (metric_id BIGINT PRIMARY KEY, total_cnt INT);', 'postgresql');
    assert.equal(clean.ok, true);
    assert.equal(clean.counts.totalSensitive, 0);
    assert.equal(clean.maskingViews.length, 0);
    assert.equal(buildReceipt({ tool: 'sensitive_masking_scan', rawInput: 'x', result: clean }).verdict, 'PASS');

    // PG 14 & PG 17 dumps
    for (const file of ['pg14-dump.sql', 'pg17-dump.sql']) {
        const res = scanSensitiveMasking(readFixture(file), 'postgresql');
        assert.equal(res.ok, true);
        assert.equal(res.metadataOnly, true);
        assert.equal(res.counts.l4, 2, `${file}: password_hash + api_secret_key`);
        assert.equal(res.counts.l3, 3, `${file}: mobile_phone + id_card_no + bank_card_number`);
        assert.equal(res.counts.l2, 3, `${file}: full_name + email_address + home_address`);
        assert.equal(res.maskingViews.length, 1);
        assert.equal(res.maskingViews[0].viewName, 'v_masked_customer_profile');
        assert.match(res.maskingViews[0].sql, /CREATE OR REPLACE VIEW "v_masked_customer_profile" AS/);
        assert.match(res.maskingViews[0].sql, /CAST\(NULL AS TEXT\) AS "password_hash"/);
        assert.match(res.maskingViews[0].sql, /SPLIT_PART/);
    }

    // MySQL 8.0 & MySQL 8.4 dumps
    for (const file of ['mysql80-dump.sql', 'mysql84-dump.sql']) {
        const res = scanSensitiveMasking(readFixture(file), 'mysql');
        assert.equal(res.ok, true);
        assert.equal(res.counts.l4, 2, `${file}: password_hash + access_token`);
        assert.equal(res.counts.l3, 3, `${file}: phone_no + id_card + bank_account`);
        assert.equal(res.counts.l2, 3, `${file}: real_name + email + ip_address`);
        assert.equal(res.findings.find((f) => f.column === 'ip_address')?.category, 'IP_DEVICE');
        assert.equal(res.maskingViews.length, 1);
        assert.equal(res.maskingViews[0].viewName, 'v_masked_customer_profile');
        assert.match(res.maskingViews[0].sql, /CREATE OR REPLACE VIEW `v_masked_customer_profile` AS/);
        assert.match(res.maskingViews[0].sql, /CAST\(NULL AS CHAR\(1\)\) AS `password_hash`/);
        assert.match(res.maskingViews[0].sql, /SUBSTRING_INDEX/);
    }
});

test('SHA-256 receipt is deterministic across repeated runs', () => {
    const sql = 'SELECT id FROM orders WHERE id = 1;';
    const r1 = buildReceipt({ tool: 'sql_readonly_review', rawInput: sql, result: reviewSqlReadonly(sql, 'postgresql') });
    const r2 = buildReceipt({ tool: 'sql_readonly_review', rawInput: sql, result: reviewSqlReadonly(sql, 'postgresql') });
    assert.equal(r1.schema_version, 'surinch.receipt.h1');
    assert.equal(r1.input_sha256, r2.input_sha256);
    assert.equal(r1.output_sha256, r2.output_sha256);
    assert.equal(r1.verdict, 'PASS');
});

test('MCP JSON-RPC 2.0 server lists 3 tools, executes them with receipts, and handles errors', () => {
    const initRes = handleJsonRpcRequest({ jsonrpc: '2.0', id: 0, method: 'initialize' });
    assert.equal(initRes.result.serverInfo.name, '@surinch/db-guard-mcp');

    const listRes = handleJsonRpcRequest({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    assert.equal(listRes.result.tools.length, 3);
    assert.deepEqual(
        listRes.result.tools.map((t) => t.name),
        ['ddl_governance_check', 'sql_readonly_review', 'sensitive_masking_scan']
    );

    const ddlRes = handleJsonRpcRequest({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
            name: 'ddl_governance_check',
            arguments: { ddl: 'CREATE TABLE bad_t (pay_amount FLOAT);', dialect: 'mysql' },
        },
    });
    assert.equal(ddlRes.result.isError, false);
    const ddlParsed = JSON.parse(ddlRes.result.content[0].text);
    assert.equal(ddlParsed.result.counts.p0, 2);
    assert.equal(ddlParsed.receipt.verdict, 'BLOCK');

    const maskRes = handleJsonRpcRequest({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
            name: 'sensitive_masking_scan',
            arguments: { ddl: readFixture('pg17-dump.sql'), dialect: 'postgresql' },
        },
    });
    assert.equal(maskRes.result.isError, false);
    const maskParsed = JSON.parse(maskRes.result.content[0].text);
    assert.equal(maskParsed.result.counts.l4, 2);
    assert.equal(maskParsed.receipt.verdict, 'BLOCK');
    assert.equal(maskParsed.receipt.input_sha256.length, 64);

    // Fault injection via MCP
    const badDialectRes = handleJsonRpcRequest({
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: {
            name: 'sensitive_masking_scan',
            arguments: { ddl: 'CREATE TABLE t (id INT);', dialect: 'oracle' },
        },
    });
    assert.equal(badDialectRes.result.isError, true);
    const badParsed = JSON.parse(badDialectRes.result.content[0].text);
    assert.equal(badParsed.result.errorCode, 'UNSUPPORTED_DIALECT');
    assert.equal(badParsed.receipt.verdict, 'INVALID_INPUT');
});

test('CLI and MCP stdio subprocesses work end-to-end with proper exit codes', () => {
    const cliPath = path.join(PKG_ROOT, 'bin', 'cli.mjs');
    const mcpPath = path.join(PKG_ROOT, 'bin', 'mcp-server.mjs');

    const cliOk = spawnSync(process.execPath, [cliPath, 'sql-review', '--dialect', 'postgresql', '--receipt'], {
        input: 'SELECT id FROM orders WHERE id = 1;',
        encoding: 'utf8',
    });
    assert.equal(cliOk.status, 0);
    assert.equal(JSON.parse(cliOk.stdout).receipt.verdict, 'PASS');

    const cliBlock = spawnSync(process.execPath, [cliPath, 'mask-scan', '--dialect', 'mysql', '--file', path.join(FIXTURES_DIR, 'mysql84-dump.sql'), '--receipt'], {
        encoding: 'utf8',
    });
    assert.equal(cliBlock.status, 1);
    assert.equal(JSON.parse(cliBlock.stdout).result.counts.l4, 2);

    const cliInvalid = spawnSync(process.execPath, [cliPath, 'ddl-check', '--dialect', 'oracle'], {
        input: 'CREATE TABLE t (id INT);',
        encoding: 'utf8',
    });
    assert.equal(cliInvalid.status, 2);

    const mcpStdio = spawnSync(process.execPath, [mcpPath], {
        input: `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })}\n`,
        encoding: 'utf8',
    });
    assert.equal(mcpStdio.status, 0);
    const line = JSON.parse(mcpStdio.stdout.trim());
    assert.equal(line.result.tools.length, 3);
});

test('Publishable package files contain no local host paths or embedded credentials', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(PKG_ROOT, 'package.json'), 'utf8'));
    const forbidden = [/\/Users\//, /\/home\/[a-z]/, /ghp_[A-Za-z0-9]{20,}/, /sk-[A-Za-z0-9]{20,}/];
    const filesToCheck = [];
    for (const entry of pkg.files) {
        const full = path.join(PKG_ROOT, entry);
        if (fs.statSync(full).isDirectory()) {
            for (const f of fs.readdirSync(full)) filesToCheck.push(path.join(full, f));
        } else {
            filesToCheck.push(full);
        }
    }
    for (const file of filesToCheck) {
        const content = fs.readFileSync(file, 'utf8');
        for (const re of forbidden) {
            assert.equal(re.test(content), false, `Forbidden pattern ${re} found in ${path.relative(PKG_ROOT, file)}`);
        }
    }
});
