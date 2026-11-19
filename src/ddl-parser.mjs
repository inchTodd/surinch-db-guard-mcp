export const SUPPORTED_DDL_DIALECTS = new Set(['mysql', 'postgresql', 'doris']);

export function unquoteIdent(raw) {
    return String(raw || '').trim().replace(/^[`"'[\]]+|[`"'[\]]+$/g, '');
}

export function normalizeTableName(raw) {
    const parts = String(raw || '').trim().split('.').map(unquoteIdent).filter(Boolean);
    return parts.length > 1 ? parts[parts.length - 1] : parts[0] || '';
}

export function stripCommentsPreservingStrings(sql) {
    let out = '';
    let i = 0;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];
        const next = sql[i + 1];
        if (ch === "'" || ch === '"') {
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

export function splitTopLevelItems(body) {
    const items = [];
    let current = '';
    let depth = 0;
    let i = 0;
    const n = body.length;
    while (i < n) {
        const ch = body[i];
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

export function parseDdlTables(rawSql, dialect = 'mysql') {
    const clean = stripCommentsPreservingStrings(String(rawSql || ''));

    const alterPkTables = new Set();
    for (const m of clean.matchAll(/ALTER\s+TABLE\s+(?:ONLY\s+)?([`"'\w.]+)\s+ADD\s+(?:CONSTRAINT\s+[`"'\w]+\s+)?PRIMARY\s+KEY\s*\(/gi)) {
        alterPkTables.add(normalizeTableName(m[1]).toLowerCase());
    }

    const commentedTables = new Set();
    for (const m of clean.matchAll(/COMMENT\s+ON\s+TABLE\s+([`"'\w.]+)\s+IS\s+'([^']*)'/gi)) {
        commentedTables.add(normalizeTableName(m[1]).toLowerCase());
    }

    const colCommentMap = new Map();
    for (const m of clean.matchAll(/COMMENT\s+ON\s+COLUMN\s+([`"'\w.]+)\s+IS\s+'([^']*)'/gi)) {
        const parts = m[1].split('.').map((p) => unquoteIdent(p).toLowerCase()).filter(Boolean);
        if (parts.length >= 2) {
            colCommentMap.set(`${parts[parts.length - 2]}.${parts[parts.length - 1]}`, m[2]);
        }
    }

    const tables = [];
    for (const match of clean.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`"'\w.]+)\s*\(/gi)) {
        const rawTableRef = match[1];
        const tableName = normalizeTableName(rawTableRef);
        const tableKey = tableName.toLowerCase();
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
            const colMatch = item.match(/^([`"'\w]+)\s+([a-zA-Z][a-zA-Z0-9_\s]*(?:\([^)]*\))?)/);
            if (!colMatch) continue;
            const colName = unquoteIdent(colMatch[1]);
            const rawType = colMatch[2].trim();
            const inlineCommentMatch = item.match(/\bCOMMENT\s+'([^']*)'/i);
            const pgComment = colCommentMap.get(`${tableKey}.${colName.toLowerCase()}`) || '';
            const comment = inlineCommentMatch ? inlineCommentMatch[1] : pgComment;
            cols.push({
                name: colName,
                rawType,
                comment,
                hasInlineComment: Boolean(comment),
                hasInlinePk: /\bPRIMARY\s+KEY\b/i.test(item),
            });
        }

        const hasPk = hasTablePk || cols.some((c) => c.hasInlinePk) || alterPkTables.has(tableKey) || inheritedLike || hasDorisKey;
        const hasTableComment = hasTailComment || commentedTables.has(tableKey);

        tables.push({
            rawRef: rawTableRef,
            name: tableName,
            columns: cols,
            hasPrimaryKey: hasPk,
            inheritedLike,
            hasTableComment,
        });
    }

    return tables;
}
