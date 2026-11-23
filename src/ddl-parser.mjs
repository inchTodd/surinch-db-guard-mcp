export const SUPPORTED_DDL_DIALECTS = new Set(['mysql', 'postgresql', 'doris']);

export function unquoteIdent(raw) {
    return String(raw || '').trim().replace(/^[`"'[\]]+|[`"'[\]]+$/g, '');
}

export function splitTableRef(raw) {
    const parts = String(raw || '')
        .trim()
        .split('.')
        .map(unquoteIdent)
        .filter(Boolean);
    if (parts.length >= 2) {
        const schema = parts[parts.length - 2];
        const name = parts[parts.length - 1];
        return { schema, name, qualifiedName: `${schema}.${name}` };
    }
    const name = parts[0] || '';
    return { schema: null, name, qualifiedName: name };
}

export function normalizeTableName(raw) {
    return splitTableRef(raw).name;
}

/**
 * Try to match a PostgreSQL dollar-quote delimiter at index `i`, e.g. `$$` or `$tag$`.
 * Returns the full delimiter string (e.g. `$$` or `$fn$`) or null.
 */
export function matchDollarQuoteTag(sql, i) {
    if (sql[i] !== '$') return null;
    const sub = sql.slice(i);
    const m = sub.match(/^\$([A-Za-z_][A-Za-z0-9_]*)?\$/);
    return m ? m[0] : null;
}

export function stripCommentsPreservingStrings(sql) {
    let out = '';
    let i = 0;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];
        const next = sql[i + 1];

        // Dollar-quoted string ($tag$...$tag$)
        if (ch === '$') {
            const tag = matchDollarQuoteTag(sql, i);
            if (tag) {
                const closeIdx = sql.indexOf(tag, i + tag.length);
                if (closeIdx >= 0) {
                    out += sql.slice(i, closeIdx + tag.length);
                    i = closeIdx + tag.length;
                    continue;
                }
                // Unclosed dollar quote: preserve rest verbatim
                out += sql.slice(i);
                break;
            }
        }

        if (ch === "'" || ch === '"' || ch === '`') {
            const quote = ch;
            out += ch;
            i += 1;
            while (i < n) {
                const c = sql[i];
                out += c;
                if (c === '\\' && i + 1 < n) {
                    out += sql[i + 1];
                    i += 2;
                    continue;
                }
                if (c === quote) {
                    if (sql[i + 1] === quote) {
                        out += sql[i + 1];
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if (ch === '-' && next === '-') {
            while (i < n && sql[i] !== '\n') i += 1;
            continue;
        }
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i += 1;
            i += 2;
            continue;
        }
        out += ch;
        i += 1;
    }
    return out;
}

export function splitSqlStatementsLexical(sql) {
    const statements = [];
    let current = '';
    let i = 0;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];

        if (ch === '$') {
            const tag = matchDollarQuoteTag(sql, i);
            if (tag) {
                const closeIdx = sql.indexOf(tag, i + tag.length);
                if (closeIdx >= 0) {
                    current += sql.slice(i, closeIdx + tag.length);
                    i = closeIdx + tag.length;
                    continue;
                }
                current += sql.slice(i);
                break;
            }
        }

        if (ch === "'" || ch === '"' || ch === '`') {
            const quote = ch;
            current += ch;
            i += 1;
            while (i < n) {
                const c = sql[i];
                current += c;
                if (c === '\\' && i + 1 < n) {
                    current += sql[i + 1];
                    i += 2;
                    continue;
                }
                if (c === quote) {
                    if (sql[i + 1] === quote) {
                        current += sql[i + 1];
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        if (ch === ';') {
            const trimmed = current.trim();
            if (trimmed) statements.push(trimmed);
            current = '';
            i += 1;
            continue;
        }

        current += ch;
        i += 1;
    }
    const last = current.trim();
    if (last) statements.push(last);
    return statements;
}

export function splitTopLevelItems(body) {
    const items = [];
    let current = '';
    let depth = 0;
    let i = 0;
    const n = body.length;
    while (i < n) {
        const ch = body[i];
        if (ch === '$') {
            const tag = matchDollarQuoteTag(body, i);
            if (tag) {
                const closeIdx = body.indexOf(tag, i + tag.length);
                if (closeIdx >= 0) {
                    current += body.slice(i, closeIdx + tag.length);
                    i = closeIdx + tag.length;
                    continue;
                }
            }
        }
        if (ch === "'" || ch === '"' || ch === '`') {
            const quote = ch;
            current += ch;
            i += 1;
            while (i < n) {
                const c = body[i];
                current += c;
                if (c === '\\' && i + 1 < n) {
                    current += body[i + 1];
                    i += 2;
                    continue;
                }
                if (c === quote) {
                    if (body[i + 1] === quote) {
                        current += body[i + 1];
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if (ch === '(') depth += 1;
        else if (ch === ')' && depth > 0) depth -= 1;
        if (ch === ',' && depth === 0) {
            const trimmed = current.trim();
            if (trimmed) items.push(trimmed);
            current = '';
        } else {
            current += ch;
        }
        i += 1;
    }
    const last = current.trim();
    if (last) items.push(last);
    return items;
}

export function extractParenBlock(sql, openIdx) {
    let depth = 0;
    let i = openIdx;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];
        if (ch === '$') {
            const tag = matchDollarQuoteTag(sql, i);
            if (tag) {
                const closeIdx = sql.indexOf(tag, i + tag.length);
                if (closeIdx >= 0) {
                    i = closeIdx + tag.length;
                    continue;
                }
            }
        }
        if (ch === "'" || ch === '"' || ch === '`') {
            const quote = ch;
            i += 1;
            while (i < n) {
                const c = sql[i];
                if (c === '\\' && i + 1 < n) {
                    i += 2;
                    continue;
                }
                if (c === quote) {
                    if (sql[i + 1] === quote) {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if (ch === '(') depth += 1;
        else if (ch === ')') {
            depth -= 1;
            if (depth === 0) return [sql.slice(openIdx + 1, i), i];
        }
        i += 1;
    }
    return ['', -1];
}

const COL_CONSTRAINT_STOP_WORDS = new Set([
    'NOT', 'NULL', 'DEFAULT', 'PRIMARY', 'UNIQUE', 'CHECK', 'REFERENCES',
    'COMMENT', 'AUTO_INCREMENT', 'GENERATED', 'COLLATE', 'UNSIGNED',
    'ZEROFILL', 'ON', 'CONSTRAINT', 'STORED', 'VIRTUAL', 'AS', 'INVISIBLE',
    'VISIBLE', 'KEY', 'USING', 'ENCODE', 'COMPRESSION',
]);

function extractColumnType(afterName) {
    const trimmed = String(afterName || '').trim();
    if (!trimmed) return '';
    // Tokenize words & parenthesized precision segments until a constraint keyword
    const tokens = [];
    let i = 0;
    const n = trimmed.length;
    while (i < n) {
        while (i < n && /\s/.test(trimmed[i])) i += 1;
        if (i >= n) break;
        if (trimmed[i] === '(') {
            const [, closeIdx] = extractParenBlock(trimmed, i);
            if (closeIdx < 0) break;
            if (tokens.length > 0) {
                tokens[tokens.length - 1] += trimmed.slice(i, closeIdx + 1);
            }
            i = closeIdx + 1;
            // After type(...), check for array brackets [] or PG "with/without time zone"
            while (i < n && /\s/.test(trimmed[i])) i += 1;
            if (trimmed.slice(i, i + 2) === '[]') {
                tokens[tokens.length - 1] += '[]';
                i += 2;
                continue;
            }
            const tzMatch = trimmed.slice(i).match(/^(?:with(?:out)?\s+time\s+zone)\b/i);
            if (tzMatch) {
                tokens.push(tzMatch[0]);
                i += tzMatch[0].length;
            }
            break;
        }
        const wordMatch = trimmed.slice(i).match(/^([a-zA-Z_][a-zA-Z0-9_]*(?:\[\])?)/);
        if (!wordMatch) break;
        const word = wordMatch[1];
        const upper = word.toUpperCase();
        // Allow "CHARACTER SET" to stop (column charset, not type "character varying")
        if (upper === 'CHARACTER' && /^CHARACTER\s+SET\b/i.test(trimmed.slice(i))) {
            break;
        }
        if (tokens.length > 0 && COL_CONSTRAINT_STOP_WORDS.has(upper)) {
            break;
        }
        tokens.push(word);
        i += word.length;
        // Multi-word SQL type continuations: double precision, character varying, bit varying,
        // timestamp/time with(out) time zone, national varchar, tiny/small/medium/big int
        if (tokens.length === 1) {
            const rest = trimmed.slice(i).trimStart();
            if (
                (upper === 'DOUBLE' && /^PRECISION\b/i.test(rest)) ||
                ((upper === 'CHARACTER' || upper === 'BIT') && /^VARYING\b/i.test(rest)) ||
                ((upper === 'TIMESTAMP' || upper === 'TIME') && /^WITH(?:OUT)?\s+TIME\s+ZONE\b/i.test(rest)) ||
                (upper === 'NATIONAL' && /^(?:CHARACTER|CHAR|VARCHAR)\b/i.test(rest))
            ) {
                continue;
            }
            // If next char is '(', loop once more to attach precision like VARCHAR(64)
            if (rest.startsWith('(')) continue;
            break;
        }
        // Handle "timestamp with time zone" multi-word continuation
        if (upper === 'WITH' || upper === 'WITHOUT' || upper === 'TIME') {
            continue;
        }
        const restAfter = trimmed.slice(i).trimStart();
        if (restAfter.startsWith('(')) continue;
        break;
    }
    return tokens.join(' ').trim();
}

function extractSqlStringValue(rawText, startIdx) {
    let i = startIdx;
    while (i < rawText.length && /\s/.test(rawText[i])) i += 1;
    if (rawText[i] === "'") {
        let val = '';
        i += 1;
        while (i < rawText.length) {
            const c = rawText[i];
            if (c === '\\' && i + 1 < rawText.length) {
                val += rawText[i + 1];
                i += 2;
                continue;
            }
            if (c === "'") {
                if (rawText[i + 1] === "'") {
                    val += "'";
                    i += 2;
                    continue;
                }
                return val;
            }
            val += c;
            i += 1;
        }
        return null;
    }
    if (rawText[i] === '$') {
        const tag = matchDollarQuoteTag(rawText, i);
        if (tag) {
            const closeIdx = rawText.indexOf(tag, i + tag.length);
            if (closeIdx >= 0) {
                return rawText.slice(i + tag.length, closeIdx);
            }
        }
    }
    return null;
}

const CREATE_TABLE_RE = /CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL)\s+)?(?:(?:TEMP|TEMPORARY|UNLOGGED)\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`"'\w.]+)\s*\(/gi;

const BENIGN_DUMP_STMT_RE = /^(?:SET\b|USE\b|COMMENT\s+ON\b|CREATE\s+(?:UNIQUE\s+)?INDEX\b|CREATE\s+(?:OR\s+REPLACE\s+)?(?:SEQUENCE|SCHEMA|EXTENSION|TYPE|DOMAIN)\b|ALTER\s+(?:SEQUENCE|SCHEMA|TYPE|DOMAIN|INDEX|DATABASE)\b|DROP\s+(?:TABLE|INDEX|SEQUENCE|SCHEMA|TYPE|VIEW)\b|LOCK\s+TABLES\b|UNLOCK\s+TABLES\b|SELECT\s+pg_catalog\.set_config\s*\(|START\s+TRANSACTION\b|BEGIN\b|COMMIT\b|GRANT\b|REVOKE\b)/i;

function stripPsqlMetaLines(sql) {
    return sql
        .split('\n')
        .filter((line) => !/^\s*\\[a-zA-Z]/.test(line))
        .join('\n');
}

export function findUnparsedDdlStatements(rawSql) {
    const clean = stripPsqlMetaLines(stripCommentsPreservingStrings(String(rawSql || '')));
    const statements = splitSqlStatementsLexical(clean);
    const unparsed = [];

    for (let idx = 0; idx < statements.length; idx += 1) {
        const stmt = statements[idx].trim();
        if (!stmt) continue;

        // Valid CREATE TABLE (...) with balanced parens
        const createStart = stmt.match(
            /^CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL)\s+)?(?:(?:TEMP|TEMPORARY|UNLOGGED)\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`"'\w.]+)\s*\(/i
        );
        if (createStart) {
            const openIdx = createStart[0].length - 1;
            const [, closeIdx] = extractParenBlock(stmt, openIdx);
            if (closeIdx >= 0) continue;
        }

        // Valid ALTER TABLE
        if (/^ALTER\s+TABLE\b/i.test(stmt)) continue;

        // Benign pg_dump / mysqldump boilerplate
        if (BENIGN_DUMP_STMT_RE.test(stmt)) continue;

        unparsed.push({
            statementIndex: idx + 1,
            preview: stmt.slice(0, 120),
            isCreateTableVariant: /^CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL)\s+)?(?:(?:TEMP|TEMPORARY|UNLOGGED)\s+)?TABLE\b/i.test(stmt),
        });
    }

    return unparsed;
}

export function parseDdlTables(rawSql, dialect = 'mysql') {
    const clean = stripPsqlMetaLines(stripCommentsPreservingStrings(String(rawSql || '')));

    const alterPkTables = new Set();
    for (const m of clean.matchAll(/ALTER\s+TABLE\s+(?:ONLY\s+)?([`"'\w.]+)\s+ADD\s+(?:CONSTRAINT\s+[`"'\w]+\s+)?PRIMARY\s+KEY\s*\(/gi)) {
        const ref = splitTableRef(m[1]);
        alterPkTables.add(ref.name.toLowerCase());
        alterPkTables.add(ref.qualifiedName.toLowerCase());
    }

    const commentedTables = new Set();
    for (const m of clean.matchAll(/COMMENT\s+ON\s+TABLE\s+([`"'\w.]+)\s+IS\s+/gi)) {
        const val = extractSqlStringValue(clean, (m.index ?? 0) + m[0].length);
        if (val !== null && val.length > 0) {
            const ref = splitTableRef(m[1]);
            commentedTables.add(ref.name.toLowerCase());
            commentedTables.add(ref.qualifiedName.toLowerCase());
        }
    }

    const colCommentMap = new Map();
    for (const m of clean.matchAll(/COMMENT\s+ON\s+COLUMN\s+([`"'\w.]+)\s+IS\s+/gi)) {
        const val = extractSqlStringValue(clean, (m.index ?? 0) + m[0].length);
        if (val === null) continue;
        const parts = m[1].split('.').map((p) => unquoteIdent(p).toLowerCase()).filter(Boolean);
        if (parts.length >= 2) {
            const colKey = parts[parts.length - 1];
            const tblKey = parts[parts.length - 2];
            colCommentMap.set(`${tblKey}.${colKey}`, val);
            if (parts.length >= 3) {
                const schemaKey = parts[parts.length - 3];
                colCommentMap.set(`${schemaKey}.${tblKey}.${colKey}`, val);
            }
        }
    }

    const tables = [];
    for (const match of clean.matchAll(CREATE_TABLE_RE)) {
        const rawTableRef = match[1];
        const ref = splitTableRef(rawTableRef);
        const tableName = ref.name;
        const tableKey = tableName.toLowerCase();
        const qualifiedKey = ref.qualifiedName.toLowerCase();
        const openParenIdx = (match.index ?? 0) + match[0].length - 1;
        const [body, closeIdx] = extractParenBlock(clean, openParenIdx);
        if (closeIdx < 0) continue;

        const tailEnd = clean.indexOf(';', closeIdx);
        const tail = clean.slice(closeIdx + 1, tailEnd >= 0 ? tailEnd : clean.length);
        const hasTailComment = /\bCOMMENT\s*=?\s*'[^']+'/i.test(tail);
        const hasDorisKey = dialect === 'doris' && /\b(?:UNIQUE|AGGREGATE|DUPLICATE)\s+KEY\s*\(/i.test(tail);

        const items = splitTopLevelItems(body);
        const cols = [];
        let hasTablePk = false;
        let inheritedLike = false;

        for (const item of items) {
            if (/^LIKE\s+/i.test(item)) {
                inheritedLike = true;
                continue;
            }
            if (/^(?:CONSTRAINT\s+[`"'\w]+\s+)?PRIMARY\s+KEY\s*\(/i.test(item)) {
                hasTablePk = true;
                continue;
            }
            if (/^(?:CONSTRAINT|UNIQUE|KEY|INDEX|FULLTEXT|SPATIAL|FOREIGN\s+KEY|CHECK|PERIOD)\b/i.test(item)) {
                continue;
            }
            // Support Unicode / Chinese column identifiers as well as quoted/ASCII identifiers
            const nameMatch = item.match(/^(`[^`]+`|"[^"]+"|'[^']+'|[^\s,(]+)\s+([\s\S]+)$/);
            if (!nameMatch) continue;
            const colName = unquoteIdent(nameMatch[1]);
            const rest = nameMatch[2];
            const rawType = extractColumnType(rest);
            if (!rawType) continue;

            const inlineCommentMatch = item.match(/\bCOMMENT\s+'([^']*)'/i);
            const pgComment =
                colCommentMap.get(`${qualifiedKey}.${colName.toLowerCase()}`) ||
                colCommentMap.get(`${tableKey}.${colName.toLowerCase()}`) ||
                '';
            const comment = inlineCommentMatch ? inlineCommentMatch[1] : pgComment;
            cols.push({
                name: colName,
                rawType,
                comment,
                hasInlineComment: Boolean(comment),
                hasInlinePk: /\bPRIMARY\s+KEY\b/i.test(item),
            });
        }

        const hasPk =
            hasTablePk ||
            cols.some((c) => c.hasInlinePk) ||
            alterPkTables.has(qualifiedKey) ||
            alterPkTables.has(tableKey) ||
            inheritedLike ||
            hasDorisKey;
        const hasTableComment =
            hasTailComment ||
            commentedTables.has(qualifiedKey) ||
            commentedTables.has(tableKey);

        tables.push({
            rawRef: rawTableRef,
            schema: ref.schema,
            name: tableName,
            qualifiedName: ref.qualifiedName,
            columns: cols,
            hasPrimaryKey: hasPk,
            inheritedLike,
            hasTableComment,
        });
    }

    return tables;
}
