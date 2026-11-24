# @surinch/db-guard-mcp

> **Local-first, zero-dependency deterministic DDL governance scorer, SQL readonly safety reviewer, and metadata-only sensitive masking scanner (CLI + MCP Server) with SHA-256 verifiable receipts.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](#)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-active-0f766e.svg)](https://registry.modelcontextprotocol.io/v0/servers/io.github.inchTodd%2Fsurinch-db-guard-mcp)
[![inchTodd/surinch-db-guard-mcp MCP server](https://glama.ai/mcp/servers/inchTodd/surinch-db-guard-mcp/badges/score.svg)](https://glama.ai/mcp/servers/inchTodd/surinch-db-guard-mcp)

`@surinch/db-guard-mcp` gives AI coding agents (Cursor, Claude Desktop, Windsurf, Antigravity, DSH) and CI pipelines a **deterministic, zero-hallucination database safety boundary**. Everything runs locally in Node.js with zero external network calls, zero database write privileges, and cryptographically reproducible `surinch.receipt.h1` SHA-256 audit receipts.

---

## Core Tools (MCP & CLI)

| MCP Tool | CLI Subcommand | What It Does | Hard Safety Guarantees |
| --- | --- | --- | --- |
| `ddl_governance_check` | `ddl-check` | Scores `CREATE TABLE` & `ALTER TABLE` DDL (`mysql`, `postgresql`, `doris`) across 5 weighted dimensions (`25% naming`, `20% comments`, `20% primary key`, `20% audit monitoring`, `15% type precision`) plus `ALTER TABLE` lock-risk detection (MySQL `MODIFY/CHANGE`, `ADD/DROP PRIMARY KEY`, `ADD FOREIGN KEY`, `CONVERT TO CHARACTER SET`, `ENGINE=`, `ALGORITHM=COPY`; PostgreSQL `ALTER COLUMN ... TYPE`, `SET NOT NULL` sequential `NOT VALID` + `VALIDATE`, inline `REFERENCES`, `CHECK` without `NOT VALID`, volatile `DEFAULT`). Supports real `pg_dump` (PG 14–17) and `mysqldump` (MySQL 8.0/8.4). | Flags missing PKs, `FLOAT`/`DOUBLE` monetary columns, and table-rewriting `ALTER TABLE` locks as `P0`/`P1`. Rejects empty input, comment-only SQL, unrecognized statements (`UNPARSED_STATEMENT`), invalid `.surinchrc.json`, and unsupported dialects with explicit error codes. |
| `sql_readonly_review` | `sql-review` | **Allowlist-first (default-deny)** static readonly safety gate, `ALTER TABLE` lock-risk detector, and anti-pattern reviewer (`mysql`, `postgresql`). Lexically handles comments, string literals, and PostgreSQL dollar-quoted blocks (`$$...$$`). | Permits only pure `SELECT`, readonly `WITH`, `SHOW`, `DESCRIBE`, and non-`ANALYZE` `EXPLAIN` (correctly allowing `EXPLAIN (ANALYZE false)`). Blocks `DO $$ ... $$`, write/DDL/admin statements (`COPY`, `LOAD DATA`, `FLUSH`, `SET`, `KILL`), data-modifying CTEs, `SELECT ... INTO`, row-locking `FOR UPDATE`, side-effect functions (`pg_sleep`, `pg_terminate_backend`, `SLEEP`), and `EXPLAIN ANALYZE` as `P0`. |
| `sensitive_masking_scan` | `mask-scan` | Metadata-only sensitive column classifier (`L4` credentials/secrets/salts, `L3` national ID / bank / salary / phone, `L2` email / name / DOB / address / IP / social IDs + Chinese column names + custom regex via `.surinchrc.json`) and schema-aware `CREATE VIEW` masking SQL generator (`mysql`, `postgresql`, `doris`). | **Never touches sample row data**—inspects schema metadata only. Preserves source schemas (`"a"."v_masked_customer"`), emits safe `CREATE VIEW` by default (`--replace-view` opt-in), and validates `viewPrefix` against SQL injection. |

### Verifiable Receipt (`surinch.receipt.h1`) & Trust Model

Every MCP call and CLI `--receipt` invocation emits a deterministic receipt bound to raw input, dialect, engine version, and normalized rule config:

```json
{
  "schema_version": "surinch.receipt.h1",
  "tool": "ddl_governance_check",
  "dialect": "postgresql",
  "engine_version": "0.3.0",
  "verdict": "PASS",
  "input_sha256": "<sha256 of raw input bytes>",
  "config_sha256": "<sha256 of canonical normalized config>",
  "context_sha256": "<sha256 of {tool, dialect, engine_version, input_sha256, config_sha256}>",
  "output_sha256": "<sha256 of canonical sorted-key JSON result>",
  "generated_at": "2026-11-23T12:00:00.000Z"
}
```

**Trust Model**:
- Comparing hashes (`surinch-verify receipt --receipt ... --input ... --result ...`) proves **mutual integrity/consistency** (`INTEGRITY_ONLY`), not provenance.
- To independently prove an engine produced the verdict, re-run the engine with `@surinch/verifiable-core` in rerun mode (`surinch-verify receipt --receipt receipt.json --input schema.sql --rerun --dialect postgresql`) and/or verify an Ed25519 receipt signature (`--public-key`).

---

## One-Click MCP Client Configurations

> **Prerequisites**: Node.js `>= 20.0.0`. No API keys, no database credentials, and no background daemon required.

### 1. Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "surinch-db-guard": {
      "command": "npx",
      "args": ["-y", "@surinch/db-guard-mcp"]
    }
  }
}
```

### 2. Claude Desktop (`claude_desktop_config.json`)

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "surinch-db-guard": {
      "command": "npx",
      "args": ["-y", "@surinch/db-guard-mcp"]
    }
  }
}
```

### 3. Windsurf (`~/.codeium/windsurf/mcp_config.json`)

```json
{
  "mcpServers": {
    "surinch-db-guard": {
      "command": "npx",
      "args": ["-y", "@surinch/db-guard-mcp"]
    }
  }
}
```

### 4. Antigravity (`mcp_config.json`)

```json
{
  "mcpServers": {
    "surinch-db-guard": {
      "command": "npx",
      "args": ["-y", "@surinch/db-guard-mcp"]
    }
  }
}
```

### 5. DSH / Local Global Install

If you prefer offline execution without `npx`:

```bash
npm install -g @surinch/db-guard-mcp
```

Then configure your MCP client (`DSH` or any stdio MCP host):

```json
{
  "mcpServers": {
    "surinch-db-guard": {
      "command": "surinch-db-guard-mcp"
    }
  }
}
```

---

## CLI Usage (CI/CD & Local Terminal)

```bash
# 1. DDL governance check (exits 0=PASS/WARN, 1=P0 BLOCK, 2=INVALID_INPUT)
cat schema.sql | npx -y -p @surinch/db-guard-mcp surinch-db-guard ddl-check --dialect postgresql --receipt

# 2. SQL readonly safety review
cat query.sql | npx -y -p @surinch/db-guard-mcp surinch-db-guard sql-review --dialect mysql --receipt

# 3. Metadata-only sensitive column scan & masking VIEW SQL generation
npx -y -p @surinch/db-guard-mcp surinch-db-guard mask-scan \
  --dialect postgresql \
  --view-prefix v_masked_ \
  --file schema.sql \
  --receipt

# 4. Recursive directory batch scan with enterprise .surinchrc.json rules
npx -y -p @surinch/db-guard-mcp surinch-db-guard ddl-check \
  --dialect postgresql \
  --dir ./migrations \
  --config ./.surinchrc.json
```

### Enterprise Rule Config (`.surinchrc.json`)

```json
{
  "disabledRules": ["R03_SELECT_STAR", "DDL_MISSING_TABLE_COMMENT"],
  "severityOverrides": {
    "R07_DEEP_PAGINATION": "P0"
  },
  "customSensitivePatterns": [
    { "level": "L4", "pattern": "(?:^|_)internal_tax_token(?:$|_)", "label": "ENTERPRISE_TAX_TOKEN" }
  ]
}
```

Malformed JSON, invalid severities (`P0`/`P1`/`P2` only), or invalid regex patterns are rejected with `INVALID_CONFIG` (exit code `2`).

### GitHub Actions PR Gate (Copy & Paste)

See [examples/github-action-db-guard.yml](./examples/github-action-db-guard.yml) for a drop-in workflow that scans `migrations/**/*.sql` on every PR, blocks `P0` lock risks, and uploads the `surinch.receipt.h1` audit artifact:

```yaml
- name: Run Surinch DB Guard batch scan (--dir)
  run: |
    npx -y -p @surinch/db-guard-mcp@0.2.0 surinch-db-guard ddl-check \
      --dialect postgresql \
      --dir migrations \
      --receipt > surinch-ddl-receipt.json
```

## Programmatic ESM Usage

```js
import {
  analyzeDdlGovernance,
  reviewSqlReadonly,
  scanSensitiveMasking,
  buildReceipt,
} from '@surinch/db-guard-mcp';

const ddl = `CREATE TABLE orders_fact (
  order_id BIGINT PRIMARY KEY COMMENT 'pk',
  pay_amount DECIMAL(18,2) NOT NULL COMMENT 'amount',
  created_at DATETIME NOT NULL COMMENT 'ts'
) COMMENT='orders';`;

const result = analyzeDdlGovernance(ddl, 'mysql');
const receipt = buildReceipt({ tool: 'ddl_governance_check', rawInput: ddl, result });
console.log(result.totalScore, receipt.verdict, receipt.output_sha256);
```

---

## Security & Zero-Egress Design

- **Readonly by construction**: Never opens network sockets or database connections.
- **Metadata only**: `sensitive_masking_scan` operates purely on DDL column names/types and never ingests row values.
- **Zero third-party runtime dependencies**: Uses Node.js built-in modules (`node:crypto`, `node:fs`, `node:readline`, `node:url`) only.

## Online Tools & Enterprise Edition

- **Free browser tools (no login)**:
  - DDL Governance Check: https://surinch.com/tools/ddl-governance-check
  - SQL Readonly Review: https://surinch.com/tools/sql-readonly-review
- **DS Bot Recomputable Governance & Warehouse Delivery**: https://surinch.com/resources/dsbot-data-governance-warehouse-delivery-recomputable-report-2026

## License

Apache-2.0 © Shanghai Surinch Network Technology Co., Ltd. (上海盈尺网络科技有限公司). See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
