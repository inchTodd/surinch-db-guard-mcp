import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
    analyzeDdlGovernance,
    reviewSqlReadonly,
    scanSensitiveMasking,
    analyzeAlterLockRisks,
    validateConfig,
    loadConfigFile,
    scanDirectoryBatch,
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
        assert.equal(res.maskingViews[0].viewName, 'public.v_masked_customer_profile');
        assert.match(res.maskingViews[0].sql, /CREATE VIEW "public"\."v_masked_customer_profile" AS/);
        assert.match(res.maskingViews[0].sql, /FROM "public"\."customer_profile";/);
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
        assert.match(res.maskingViews[0].sql, /CREATE VIEW `v_masked_customer_profile` AS/);
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

test('ALTER TABLE lock-risk detection catches MySQL and PostgreSQL risks in ddl_governance_check and sql_readonly_review', () => {
    // --- MySQL positive lock risks ---
    const mysqlUnsafe = `
        ALTER TABLE orders_fact MODIFY COLUMN status VARCHAR(64) NOT NULL;
        ALTER TABLE orders_fact CHANGE COLUMN note remark TEXT;
        ALTER TABLE orders_fact ADD PRIMARY KEY (order_id);
        ALTER TABLE orders_fact ADD CONSTRAINT fk_cust FOREIGN KEY (customer_id) REFERENCES customer_profile(customer_id);
        ALTER TABLE orders_fact CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
    `;
    const mysqlDdl = analyzeDdlGovernance(mysqlUnsafe, 'mysql');
    assert.equal(mysqlDdl.ok, true);
    assert.equal(mysqlDdl.alterStatementCount, 5);
    assert.ok(mysqlDdl.totalScore < 100, 'ALTER-only DDL with lock risks must not score 100');
    const mysqlCodes = mysqlDdl.findings.map((f) => f.ruleCode);
    assert.ok(mysqlCodes.includes('MYSQL_ALTER_MODIFY_COLUMN'));
    assert.ok(mysqlCodes.includes('MYSQL_ALTER_ADD_PRIMARY_KEY'));
    assert.ok(mysqlCodes.includes('MYSQL_ALTER_ADD_FOREIGN_KEY'));
    assert.ok(mysqlCodes.includes('MYSQL_ALTER_CONVERT_CHARSET'));
    assert.equal(mysqlDdl.counts.p0, 2, 'ADD PRIMARY KEY + CONVERT TO CHARACTER SET are P0');
    assert.equal(mysqlDdl.counts.p1, 3, 'MODIFY + CHANGE + ADD FOREIGN KEY are P1');
    assert.match(mysqlDdl.findings.find((f) => f.ruleCode === 'MYSQL_ALTER_MODIFY_COLUMN').hint, /ALGORITHM=INSTANT|ALGORITHM=INPLACE, LOCK=NONE|gh-ost/);
    assert.match(mysqlDdl.findings.find((f) => f.ruleCode === 'MYSQL_ALTER_CONVERT_CHARSET').hint, /gh-ost|pt-osc/);

    // MySQL safe online MODIFY / CHANGE with explicit ALGORITHM=INPLACE, LOCK=NONE or ALGORITHM=INSTANT
    const mysqlSafe = `
        ALTER TABLE orders_fact MODIFY COLUMN status VARCHAR(64) NOT NULL, ALGORITHM=INPLACE, LOCK=NONE;
        ALTER TABLE orders_fact ADD COLUMN extra_tag VARCHAR(32) DEFAULT NULL, ALGORITHM=INSTANT;
    `;
    const mysqlSafeRes = analyzeDdlGovernance(mysqlSafe, 'mysql');
    assert.equal(mysqlSafeRes.ok, true);
    assert.equal(mysqlSafeRes.findings.length, 0);
    assert.equal(mysqlSafeRes.totalScore, 100);

    // MySQL sql_readonly_review includes BOTH readonly write block and lock-risk findings
    const mysqlSqlReview = reviewSqlReadonly('ALTER TABLE orders_fact CONVERT TO CHARACTER SET utf8mb4;', 'mysql');
    assert.equal(mysqlSqlReview.ok, true);
    assert.equal(mysqlSqlReview.readonlySafe, false);
    assert.ok(mysqlSqlReview.findings.some((f) => f.ruleCode === 'R02_WRITE_OR_DDL'));
    assert.ok(mysqlSqlReview.findings.some((f) => f.ruleCode === 'MYSQL_ALTER_CONVERT_CHARSET'));

    // --- PostgreSQL positive lock risks ---
    const pgUnsafe = `
        ALTER TABLE orders_fact ALTER COLUMN pay_amount TYPE numeric(20,4);
        ALTER TABLE orders_fact ALTER COLUMN status SET NOT NULL;
        ALTER TABLE orders_fact ADD CONSTRAINT fk_customer FOREIGN KEY (customer_id) REFERENCES customer_profile(customer_id);
        ALTER TABLE orders_fact ADD COLUMN trace_id uuid DEFAULT gen_random_uuid();
        ALTER TABLE orders_fact ADD COLUMN rand_score double precision DEFAULT random();
        ALTER TABLE orders_fact ADD COLUMN ts_now timestamptz DEFAULT clock_timestamp();
        ALTER TABLE orders_fact ADD COLUMN legacy_uuid uuid DEFAULT uuid_generate_v4();
    `;
    const pgDdl = analyzeDdlGovernance(pgUnsafe, 'postgresql');
    assert.equal(pgDdl.ok, true);
    assert.equal(pgDdl.alterStatementCount, 7);
    assert.ok(pgDdl.totalScore < 100);
    const pgCodes = pgDdl.findings.map((f) => f.ruleCode);
    assert.ok(pgCodes.includes('PG_ALTER_COLUMN_TYPE'));
    assert.ok(pgCodes.includes('PG_ALTER_SET_NOT_NULL'));
    assert.ok(pgCodes.includes('PG_ALTER_ADD_FK_WITHOUT_NOT_VALID'));
    assert.equal(pgCodes.filter((c) => c === 'PG_ALTER_ADD_COL_VOLATILE_DEFAULT').length, 4);
    assert.equal(pgDdl.counts.p0, 5, 'ALTER COLUMN TYPE + 4 volatile defaults are P0');
    assert.equal(pgDdl.counts.p1, 2, 'SET NOT NULL + FK without NOT VALID are P1');
    assert.match(pgDdl.findings.find((f) => f.ruleCode === 'PG_ALTER_COLUMN_TYPE').message, /ACCESS EXCLUSIVE/);

    // PostgreSQL safe patterns: NOT VALID check before SET NOT NULL, FK with NOT VALID, non-volatile DEFAULT
    const pgSafe = `
        ALTER TABLE orders_fact ADD CONSTRAINT chk_status_nn CHECK (status IS NOT NULL) NOT VALID;
        ALTER TABLE orders_fact VALIDATE CONSTRAINT chk_status_nn;
        ALTER TABLE orders_fact ALTER COLUMN status SET NOT NULL;
        ALTER TABLE orders_fact ADD CONSTRAINT fk_customer FOREIGN KEY (customer_id) REFERENCES customer_profile(customer_id) NOT VALID;
        ALTER TABLE orders_fact ADD COLUMN retry_count integer DEFAULT 0;
    `;
    const pgSafeRes = analyzeDdlGovernance(pgSafe, 'postgresql');
    assert.equal(pgSafeRes.ok, true);
    assert.equal(pgSafeRes.findings.length, 0);

    // PostgreSQL sql_readonly_review includes BOTH readonly write block and PG lock-risk finding
    const pgSqlReview = reviewSqlReadonly('ALTER TABLE orders_fact ALTER COLUMN pay_amount TYPE numeric(20,4);', 'postgresql');
    assert.equal(pgSqlReview.ok, true);
    assert.equal(pgSqlReview.readonlySafe, false);
    assert.ok(pgSqlReview.findings.some((f) => f.ruleCode === 'R02_WRITE_OR_DDL'));
    assert.ok(pgSqlReview.findings.some((f) => f.ruleCode === 'PG_ALTER_COLUMN_TYPE'));

    // Fault injection: ALTER TABLE inside SQL comments must NOT trigger
    const commented = `
        -- ALTER TABLE orders_fact CONVERT TO CHARACTER SET utf8mb4;
        /* ALTER TABLE orders_fact ALTER COLUMN pay_amount TYPE text; */
        SELECT id FROM orders_fact WHERE id = 1;
    `;
    const commentCheck = analyzeAlterLockRisks(commented, 'postgresql');
    assert.equal(commentCheck.alterStatementCount, 0);
    assert.equal(commentCheck.findings.length, 0);
});

test('Enterprise custom rule config (.surinchrc.json) supports disabledRules, severityOverrides, customSensitivePatterns, and rejects invalid configs', () => {
    // Fault-injection: invalid configs MUST return INVALID_CONFIG
    assert.equal(validateConfig(null).errorCode, 'INVALID_CONFIG');
    assert.equal(validateConfig([]).errorCode, 'INVALID_CONFIG');
    assert.equal(validateConfig({ disabledRules: 'R03_SELECT_STAR' }).errorCode, 'INVALID_CONFIG');
    assert.equal(validateConfig({ severityOverrides: { R03_SELECT_STAR: 'CRITICAL' } }).errorCode, 'INVALID_CONFIG');
    assert.equal(validateConfig({ customSensitivePatterns: [{ level: 'L9', pattern: 'foo', label: 'bad' }] }).errorCode, 'INVALID_CONFIG');
    assert.equal(validateConfig({ customSensitivePatterns: [{ level: 'L3', pattern: '[unclosed', label: 'bad_re' }] }).errorCode, 'INVALID_CONFIG');
    assert.equal(validateConfig({ customSensitivePatterns: [{ level: 'L3', pattern: 'foo', label: '' }] }).errorCode, 'INVALID_CONFIG');
    assert.equal(loadConfigFile('/non/existent/path/.surinchrc.json').errorCode, 'INVALID_CONFIG');

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'surinch-cfg-test-'));
    try {
        // Malformed JSON file
        const badJsonPath = path.join(tmpDir, 'bad.surinchrc.json');
        fs.writeFileSync(badJsonPath, '{ invalid json', 'utf8');
        assert.equal(loadConfigFile(badJsonPath).errorCode, 'INVALID_CONFIG');
        assert.equal(reviewSqlReadonly('SELECT 1;', 'postgresql', { config: badJsonPath }).errorCode, 'INVALID_CONFIG');

        // Valid enterprise config file
        const validCfgPath = path.join(tmpDir, '.surinchrc.json');
        const cfgObj = {
            disabledRules: ['R03_SELECT_STAR', 'DDL_MISSING_TABLE_COMMENT', 'EMAIL'],
            severityOverrides: {
                R07_DEEP_PAGINATION: 'P0',
                DDL_MISSING_AUDIT_TS: 'P2',
            },
            customSensitivePatterns: [
                { level: 'L4', pattern: '(?:^|_)internal_tax_token(?:$|_)', label: 'ENTERPRISE_TAX_TOKEN' },
                { level: 'L3', pattern: '(?:^|_)employee_badge_no(?:$|_)', label: 'EMPLOYEE_BADGE' },
            ],
        };
        fs.writeFileSync(validCfgPath, JSON.stringify(cfgObj, null, 2), 'utf8');

        // 1. sql_readonly_review with disabledRules + severityOverrides
        const sqlRes = reviewSqlReadonly('SELECT * FROM orders LIMIT 10 OFFSET 5000;', 'postgresql', { config: validCfgPath });
        assert.equal(sqlRes.ok, true);
        assert.equal(sqlRes.findings.some((f) => f.ruleCode === 'R03_SELECT_STAR'), false, 'R03_SELECT_STAR should be disabled');
        const deepPag = sqlRes.findings.find((f) => f.ruleCode === 'R07_DEEP_PAGINATION');
        assert.equal(deepPag?.severity, 'P0', 'R07_DEEP_PAGINATION should be overridden to P0');
        assert.equal(sqlRes.readonlySafe, false, 'P0 override blocks readonlySafe');

        // 2. ddl_governance_check with disabledRules + severityOverrides
        const ddlRes = analyzeDdlGovernance(`
            CREATE TABLE orders_fact (
                id BIGINT PRIMARY KEY COMMENT 'pk'
            );
        `, 'mysql', { config: validCfgPath });
        assert.equal(ddlRes.ok, true);
        assert.equal(ddlRes.findings.some((f) => f.ruleCode === 'DDL_MISSING_TABLE_COMMENT'), false);
        assert.equal(ddlRes.findings.find((f) => f.ruleCode === 'DDL_MISSING_AUDIT_TS')?.severity, 'P2');

        // 3. sensitive_masking_scan with customSensitivePatterns + disabledRules
        const maskRes = scanSensitiveMasking(`
            CREATE TABLE hr_records (
                id BIGINT PRIMARY KEY,
                email VARCHAR(128),
                employee_badge_no VARCHAR(32),
                internal_tax_token VARCHAR(128)
            );
        `, 'postgresql', { config: validCfgPath });
        assert.equal(maskRes.ok, true);
        assert.equal(maskRes.findings.some((f) => f.category === 'EMAIL'), false, 'EMAIL disabled by config');
        assert.equal(maskRes.counts.l4, 1, 'internal_tax_token classified as L4');
        assert.equal(maskRes.counts.l3, 1, 'employee_badge_no classified as L3');
        assert.equal(maskRes.maskingViews.length, 1);
        assert.match(maskRes.maskingViews[0].sql, /CAST\(NULL AS TEXT\) AS "internal_tax_token"/);

        // 4. MCP tools/call with valid and invalid config
        const mcpGood = handleJsonRpcRequest({
            jsonrpc: '2.0',
            id: 10,
            method: 'tools/call',
            params: {
                name: 'sql_readonly_review',
                arguments: {
                    sql: 'SELECT * FROM orders;',
                    dialect: 'postgresql',
                    config: { disabledRules: ['R03_SELECT_STAR'] },
                },
            },
        });
        assert.equal(mcpGood.result.isError, false);
        assert.equal(JSON.parse(mcpGood.result.content[0].text).result.findings.length, 0);

        const mcpBad = handleJsonRpcRequest({
            jsonrpc: '2.0',
            id: 11,
            method: 'tools/call',
            params: {
                name: 'sensitive_masking_scan',
                arguments: {
                    ddl: 'CREATE TABLE t (id INT);',
                    dialect: 'mysql',
                    config: { customSensitivePatterns: [{ level: 'L4', pattern: '([broken', label: 'bad' }] },
                },
            },
        });
        assert.equal(mcpBad.result.isError, true);
        const mcpBadParsed = JSON.parse(mcpBad.result.content[0].text);
        assert.equal(mcpBadParsed.result.errorCode, 'INVALID_CONFIG');
        assert.equal(mcpBadParsed.receipt.verdict, 'INVALID_INPUT');

        // 5. CLI --config with valid and invalid config
        const cliPath = path.join(PKG_ROOT, 'bin', 'cli.mjs');
        const cliCfgBlock = spawnSync(process.execPath, [cliPath, 'sql-review', '--dialect', 'postgresql', '--config', validCfgPath], {
            input: 'SELECT id FROM orders LIMIT 10 OFFSET 5000;',
            encoding: 'utf8',
        });
        assert.equal(cliCfgBlock.status, 1, 'Overridden P0 exits 1');
        assert.equal(JSON.parse(cliCfgBlock.stdout).counts.p0, 1);

        const cliCfgInvalid = spawnSync(process.execPath, [cliPath, 'sql-review', '--dialect', 'postgresql', '--config', badJsonPath], {
            input: 'SELECT 1;',
            encoding: 'utf8',
        });
        assert.equal(cliCfgInvalid.status, 2, 'Malformed config exits 2');
        assert.equal(JSON.parse(cliCfgInvalid.stdout).errorCode, 'INVALID_CONFIG');
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test('Directory batch scanning (--dir) recursively scans .sql files, emits deterministic receipt, and fails non-zero on P0/empty dir', () => {
    const cliPath = path.join(PKG_ROOT, 'bin', 'cli.mjs');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'surinch-batch-test-'));
    try {
        // 1. Empty directory -> EMPTY_DIR, exit 2 (never fake green)
        const emptyDir = path.join(tmpDir, 'empty');
        fs.mkdirSync(emptyDir);
        fs.writeFileSync(path.join(emptyDir, 'README.md'), '# not sql', 'utf8');
        const emptyRun = spawnSync(process.execPath, [cliPath, 'ddl-check', '--dialect', 'mysql', '--dir', emptyDir], {
            encoding: 'utf8',
        });
        assert.equal(emptyRun.status, 2);
        const emptyParsed = JSON.parse(emptyRun.stdout);
        assert.equal(emptyParsed.result.ok, false);
        assert.equal(emptyParsed.result.errorCode, 'EMPTY_DIR');
        assert.equal(emptyParsed.receipt.verdict, 'INVALID_INPUT');

        // 2. Non-existent directory -> INVALID_DIR, exit 2
        const missingRun = spawnSync(process.execPath, [cliPath, 'sql-review', '--dialect', 'postgresql', '--dir', path.join(tmpDir, 'does-not-exist')], {
            encoding: 'utf8',
        });
        assert.equal(missingRun.status, 2);
        assert.equal(JSON.parse(missingRun.stdout).result.errorCode, 'INVALID_DIR');

        // 3. Clean nested directory -> exit 0, PASS, deterministic receipt
        const cleanDir = path.join(tmpDir, 'clean');
        fs.mkdirSync(path.join(cleanDir, 'nested', 'sub'), { recursive: true });
        fs.writeFileSync(path.join(cleanDir, '01_orders.sql'), `
            CREATE TABLE orders_fact (
                id BIGINT PRIMARY KEY COMMENT 'pk',
                pay_amount DECIMAL(18,2) NOT NULL COMMENT 'amount',
                created_at DATETIME NOT NULL COMMENT 'ts'
            ) COMMENT='orders';
        `, 'utf8');
        fs.writeFileSync(path.join(cleanDir, 'nested', 'sub', '02_items.sql'), `
            CREATE TABLE order_items (
                item_id BIGINT PRIMARY KEY COMMENT 'pk',
                unit_price DECIMAL(18,2) NOT NULL COMMENT 'price',
                created_at DATETIME NOT NULL COMMENT 'ts'
            ) COMMENT='items';
        `, 'utf8');
        fs.writeFileSync(path.join(cleanDir, 'notes.txt'), 'ignored', 'utf8');

        const cleanRun1 = spawnSync(process.execPath, [cliPath, 'ddl-check', '--dialect', 'mysql', '--dir', cleanDir], {
            encoding: 'utf8',
        });
        const cleanRun2 = spawnSync(process.execPath, [cliPath, 'ddl-check', '--dialect', 'mysql', '--dir', cleanDir], {
            encoding: 'utf8',
        });
        assert.equal(cleanRun1.status, 0);
        const p1 = JSON.parse(cleanRun1.stdout);
        const p2 = JSON.parse(cleanRun2.stdout);
        assert.equal(p1.result.ok, true);
        assert.equal(p1.result.fileCount, 2);
        assert.deepEqual(p1.result.files.map((f) => f.file), ['01_orders.sql', 'nested/sub/02_items.sql']);
        assert.equal(p1.result.summary.passedFiles, 2);
        assert.equal(p1.receipt.schema_version, 'surinch.receipt.h1');
        assert.equal(p1.receipt.verdict, 'PASS');
        assert.equal(p1.receipt.input_sha256, p2.receipt.input_sha256);
        assert.equal(p1.receipt.output_sha256, p2.receipt.output_sha256);

        // 4. Directory with P0/BLOCK file across sql-review and mask-scan -> exit 1
        const blockDir = path.join(tmpDir, 'block-sql');
        fs.mkdirSync(blockDir);
        fs.writeFileSync(path.join(blockDir, 'a_safe.sql'), 'SELECT id FROM orders WHERE id = 1;', 'utf8');
        fs.writeFileSync(path.join(blockDir, 'b_alter.sql'), 'ALTER TABLE orders ALTER COLUMN pay_amount TYPE numeric(20,4);', 'utf8');

        const blockSqlRun = spawnSync(process.execPath, [cliPath, 'sql-review', '--dialect', 'postgresql', '--dir', blockDir], {
            encoding: 'utf8',
        });
        assert.equal(blockSqlRun.status, 1);
        const blockSqlParsed = JSON.parse(blockSqlRun.stdout);
        assert.equal(blockSqlParsed.result.summary.passedFiles, 1);
        assert.equal(blockSqlParsed.result.summary.blockedFiles, 1);
        assert.equal(blockSqlParsed.receipt.verdict, 'BLOCK');

        const maskBatch = scanDirectoryBatch({
            command: 'mask-scan',
            dirPath: FIXTURES_DIR,
            dialect: 'postgresql',
        });
        assert.equal(maskBatch.result.ok, true);
        assert.equal(maskBatch.result.fileCount, 4);
        assert.equal(maskBatch.receipt.verdict, 'BLOCK');

        // 5. Directory with an invalid/comment-only .sql file -> exit 2 (never fake green)
        const invalidFileDir = path.join(tmpDir, 'invalid-file');
        fs.mkdirSync(invalidFileDir);
        fs.writeFileSync(path.join(invalidFileDir, 'empty.sql'), '-- only comment', 'utf8');
        const invalidFileRun = spawnSync(process.execPath, [cliPath, 'ddl-check', '--dialect', 'mysql', '--dir', invalidFileDir], {
            encoding: 'utf8',
        });
        assert.equal(invalidFileRun.status, 2);
        const invalidFileParsed = JSON.parse(invalidFileRun.stdout);
        assert.equal(invalidFileParsed.result.ok, false);
        assert.equal(invalidFileParsed.result.errorCode, 'BATCH_CONTAINS_INVALID_FILES');
        assert.equal(invalidFileParsed.receipt.verdict, 'INVALID_INPUT');
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
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

test('Audit A1 & S4-1: allowlist-first SQL readonly review blocks all write/side-effect probes and allows EXPLAIN (ANALYZE false)', () => {
    const blockedProbes = [
        ['postgresql', 'DO $$ BEGIN DELETE FROM orders; END $$;'],
        ['postgresql', 'WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d;'],
        ['postgresql', 'WITH u AS (UPDATE orders SET status = 1 RETURNING *) SELECT id FROM u;'],
        ['postgresql', 'SELECT * INTO orders_backup FROM orders;'],
        ['postgresql', "COPY orders TO '/tmp/orders.csv';"],
        ['postgresql', 'SELECT pg_sleep(600);'],
        ['postgresql', 'SELECT pg_terminate_backend(12345);'],
        ['postgresql', 'SELECT id FROM orders FOR UPDATE;'],
        ['postgresql', 'SET statement_timeout = 0;'],
        ['postgresql', 'NOTIFY ch, \'payload\';'],
        ['postgresql', 'SELECT $$unclosed'],
        ['mysql', "LOAD DATA INFILE '/etc/passwd' INTO TABLE t;"],
        ['mysql', 'DO SLEEP(1000);'],
        ['mysql', 'FLUSH TABLES WITH READ LOCK;'],
        ['mysql', 'SET GLOBAL read_only = 0;'],
        ['mysql', 'STOP REPLICA;'],
        ['mysql', 'KILL 999;'],
        ['mysql', "SELECT id INTO OUTFILE '/tmp/out.txt' FROM orders;"],
        ['mysql', 'SELECT SLEEP(10);'],
    ];

    for (const [dialect, sql] of blockedProbes) {
        const r = reviewSqlReadonly(sql, dialect);
        assert.equal(r.ok, true, `Should analyze [${dialect}] ${sql}`);
        assert.equal(r.readonlySafe, false, `Must block [${dialect}] ${sql}`);
        assert.equal(r.verdict, 'WRITE_OR_DDL_BLOCKED', `Must return WRITE_OR_DDL_BLOCKED for [${dialect}] ${sql}`);
        assert.ok(r.counts.p0 >= 1, `Must have P0 finding for [${dialect}] ${sql}`);
    }

    // S4-1: EXPLAIN (ANALYZE false / off / 0) must NOT trigger R01_EXPLAIN_ANALYZE
    for (const safeExplain of [
        'EXPLAIN (ANALYZE false, FORMAT json) SELECT id FROM orders WHERE id = 1;',
        'EXPLAIN (ANALYZE off) SELECT id FROM orders WHERE id = 1;',
        'EXPLAIN (ANALYZE 0) SELECT id FROM orders WHERE id = 1;',
        'EXPLAIN SELECT id FROM orders WHERE id = 1;',
        'SHOW TABLES;',
        'DESCRIBE orders;',
    ]) {
        const r = reviewSqlReadonly(safeExplain, 'postgresql');
        assert.equal(r.ok, true);
        assert.equal(r.readonlySafe, true, `Should allow safe readonly: ${safeExplain}`);
        assert.equal(r.findings.some((f) => f.ruleCode === 'R01_EXPLAIN_ANALYZE'), false);
    }
});

test('Audit B6 & S4-3/4: ALTER lock rules, NOT VALID ordering, PG varchar widening, dollar-quoted COMMENT, and VARCHAR without length', () => {
    // MySQL misses fixed
    for (const [sql, expectedRule] of [
        ['ALTER TABLE orders DROP PRIMARY KEY;', 'MYSQL_ALTER_DROP_PRIMARY_KEY'],
        ['ALTER TABLE orders ENGINE=InnoDB;', 'MYSQL_ALTER_REBUILD_ENGINE'],
        ['ALTER TABLE orders ADD COLUMN x INT, ALGORITHM=COPY;', 'MYSQL_ALTER_ALGORITHM_COPY'],
        ['ALTER TABLE orders ADD COLUMN id INT PRIMARY KEY;', 'MYSQL_ALTER_ADD_PRIMARY_KEY'],
    ]) {
        const r = analyzeDdlGovernance(sql, 'mysql');
        assert.equal(r.ok, true);
        assert.ok(r.findings.some((f) => f.ruleCode === expectedRule), `Expected ${expectedRule} for ${sql}`);
        assert.ok(r.totalScore < 100, `Expected score < 100 for ${sql}`);
    }

    // PG misses fixed: inline REFERENCES + ADD CONSTRAINT CHECK
    const pgInlineRef = analyzeDdlGovernance('ALTER TABLE orders ADD COLUMN user_id int REFERENCES users(id);', 'postgresql');
    assert.ok(pgInlineRef.findings.some((f) => f.ruleCode === 'PG_ALTER_ADD_FK_WITHOUT_NOT_VALID'));
    const pgCheck = analyzeDdlGovernance('ALTER TABLE orders ADD CONSTRAINT chk CHECK (amount >= 0);', 'postgresql');
    assert.ok(pgCheck.findings.some((f) => f.ruleCode === 'PG_ALTER_ADD_CHECK_WITHOUT_NOT_VALID'));

    // PG NOT VALID without VALIDATE CONSTRAINT must STILL flag SET NOT NULL
    const missingValidate = analyzeDdlGovernance(`
        ALTER TABLE orders ADD CONSTRAINT chk_s CHECK (status IS NOT NULL) NOT VALID;
        ALTER TABLE orders ALTER COLUMN status SET NOT NULL;
    `, 'postgresql');
    assert.ok(missingValidate.findings.some((f) => f.ruleCode === 'PG_ALTER_SET_NOT_NULL'), 'Missing VALIDATE must not exempt SET NOT NULL');

    // PG NOT VALID placed AFTER SET NOT NULL must STILL flag SET NOT NULL
    const reversedOrder = analyzeDdlGovernance(`
        ALTER TABLE orders ALTER COLUMN status SET NOT NULL;
        ALTER TABLE orders ADD CONSTRAINT chk_s CHECK (status IS NOT NULL) NOT VALID;
        ALTER TABLE orders VALIDATE CONSTRAINT chk_s;
    `, 'postgresql');
    assert.ok(reversedOrder.findings.some((f) => f.ruleCode === 'PG_ALTER_SET_NOT_NULL'), 'Reversed order must not exempt SET NOT NULL');

    // PG varchar(50) -> varchar(500) widening does NOT rewrite table (no P0)
    const pgWiden = analyzeDdlGovernance(`
        CREATE TABLE orders (
            id BIGINT PRIMARY KEY,
            name varchar(50),
            created_at timestamptz
        );
        COMMENT ON TABLE orders IS $$orders table$$;
        COMMENT ON COLUMN orders.id IS $$pk$$;
        COMMENT ON COLUMN orders.name IS $$customer name$$;
        COMMENT ON COLUMN orders.created_at IS $$ts$$;
        ALTER TABLE orders ALTER COLUMN name TYPE varchar(500);
    `, 'postgresql');
    assert.equal(pgWiden.ok, true);
    assert.equal(pgWiden.findings.some((f) => f.ruleCode === 'PG_ALTER_COLUMN_TYPE'), false, 'Known varchar(50)->varchar(500) widening must not flag rewrite');
    // S4-3: dollar-quoted comments recognized
    assert.equal(pgWiden.tables[0].hasTableComment, true);
    assert.equal(pgWiden.tables[0].commentedColumns, 3);
    assert.equal(pgWiden.totalScore, 100);

    // Standalone PG ALTER COLUMN name TYPE varchar(500) (unknown original type) is P1, not P0
    const pgStandaloneVarchar = analyzeDdlGovernance('ALTER TABLE orders ALTER COLUMN name TYPE varchar(500);', 'postgresql');
    const typeFinding = pgStandaloneVarchar.findings.find((f) => f.ruleCode === 'PG_ALTER_COLUMN_TYPE');
    assert.equal(typeFinding?.severity, 'P1');

    // S4-4: MySQL VARCHAR without length followed by NOT NULL COMMENT
    const mysqlNoLen = analyzeDdlGovernance(`
        CREATE TABLE users (
            id BIGINT PRIMARY KEY COMMENT 'pk',
            nick VARCHAR NOT NULL COMMENT 'nick',
            created_at DATETIME COMMENT 'ts'
        ) COMMENT='users';
    `, 'mysql');
    assert.ok(mysqlNoLen.findings.some((f) => f.ruleCode === 'DDL_MYSQL_VARCHAR_LEN'));
});

test('Audit C1, C2, C3, C4, A4: receipt binding, expanded PII + schema-aware views, UNPARSED_STATEMENT, MCP ping/notifications/config-sandbox, CLI --sql & positional', () => {
    // C1: receipt binds dialect and config_sha256
    const ddl = 'CREATE TABLE bad_t (id INT);';
    const rA = buildReceipt({ tool: 'ddl_governance_check', rawInput: ddl, result: analyzeDdlGovernance(ddl, 'mysql'), dialect: 'mysql' });
    const rB = buildReceipt({
        tool: 'ddl_governance_check',
        rawInput: ddl,
        result: analyzeDdlGovernance(ddl, 'mysql', { config: { disabledRules: ['DDL_MISSING_PK'] } }),
        dialect: 'mysql',
        config: { disabledRules: ['DDL_MISSING_PK'] },
    });
    assert.equal(rA.dialect, 'mysql');
    assert.equal(rA.config_sha256.length, 64);
    assert.equal(rA.context_sha256.length, 64);
    assert.notEqual(rA.config_sha256, rB.config_sha256);
    assert.notEqual(rA.context_sha256, rB.context_sha256);

    // C2: expanded PII dictionary + Chinese columns + multi-schema collision prevention + default CREATE VIEW
    const pii = scanSensitiveMasking(`
        CREATE TABLE a.customer (
            id BIGINT PRIMARY KEY,
            first_name VARCHAR(64),
            last_name VARCHAR(64),
            birth_date DATE,
            salary DECIMAL(12,2),
            openid VARCHAR(64),
            salt VARCHAR(32),
            account_no VARCHAR(32),
            手机号 VARCHAR(20)
        );
        CREATE TABLE b.customer (
            id BIGINT PRIMARY KEY,
            email VARCHAR(128)
        );
    `, 'postgresql');
    assert.equal(pii.ok, true);
    assert.equal(pii.tables[0].sensitiveColumnCount, 8, 'All 8 PII columns in a.customer detected');
    assert.equal(pii.maskingViews.length, 2);
    assert.equal(pii.maskingViews[0].viewName, 'a.v_masked_customer');
    assert.equal(pii.maskingViews[1].viewName, 'b.v_masked_customer');
    assert.match(pii.maskingViews[0].sql, /^CREATE VIEW "a"\."v_masked_customer" AS/);
    assert.match(pii.maskingViews[0].sql, /FROM "a"\."customer";/);
    assert.doesNotMatch(pii.maskingViews[0].sql, /OR REPLACE/);

    // C3: UNLOGGED TABLE is parsed & scored; unrecognized statements (e.g. CTAS) fail explicitly with UNPARSED_STATEMENT
    const unlogged = analyzeDdlGovernance("CREATE TABLE good (id BIGINT PRIMARY KEY COMMENT 'pk', created_at DATETIME COMMENT 'c') COMMENT='g';\nCREATE UNLOGGED TABLE bad (pay_amount FLOAT);", 'postgresql');
    assert.equal(unlogged.ok, true);
    assert.equal(unlogged.tableCount, 2);
    assert.ok(unlogged.counts.p0 >= 2, 'UNLOGGED table with float money & no PK must report P0');
    const ctas = analyzeDdlGovernance("CREATE TABLE good (id BIGINT PRIMARY KEY COMMENT 'pk', created_at DATETIME COMMENT 'c') COMMENT='g';\nCREATE TABLE bad_ctas AS SELECT 1 AS pay_amount;", 'postgresql');
    assert.equal(ctas.ok, false);
    assert.equal(ctas.errorCode, 'UNPARSED_STATEMENT');

    // C4: MCP ping, notifications silence, and config path rejection
    assert.deepEqual(handleJsonRpcRequest({ jsonrpc: '2.0', id: 99, method: 'ping' }), { jsonrpc: '2.0', id: 99, result: {} });
    assert.equal(handleJsonRpcRequest({ jsonrpc: '2.0', method: 'notifications/cancelled', params: {} }), null);
    const cfgPathAttempt = handleJsonRpcRequest({
        jsonrpc: '2.0',
        id: 100,
        method: 'tools/call',
        params: { name: 'sql_readonly_review', arguments: { sql: 'SELECT 1;', dialect: 'postgresql', config: '/etc/passwd' } },
    });
    assert.equal(cfgPathAttempt.result.isError, true);
    const cfgPathParsed = JSON.parse(cfgPathAttempt.result.content[0].text);
    assert.equal(cfgPathParsed.result.errorCode, 'INVALID_CONFIG');
    assert.doesNotMatch(cfgPathParsed.result.message, /root:/, 'Must never read or leak file contents');

    // A4: CLI supports --sql and positional file path
    const cliPath = path.join(PKG_ROOT, 'bin', 'cli.mjs');
    const cliSql = spawnSync(process.execPath, [cliPath, 'sql-review', '--dialect', 'postgresql', '--sql', 'EXPLAIN ANALYZE DELETE FROM orders;'], { encoding: 'utf8' });
    assert.equal(cliSql.status, 1);
    assert.equal(JSON.parse(cliSql.stdout).readonlySafe, false);

    const cliPositional = spawnSync(process.execPath, [cliPath, 'ddl-check', '--dialect', 'postgresql', '--receipt', path.join(FIXTURES_DIR, 'pg17-dump.sql')], { encoding: 'utf8' });
    assert.equal(cliPositional.status, 1);
    assert.equal(JSON.parse(cliPositional.stdout).result.tableCount, 3);
});
