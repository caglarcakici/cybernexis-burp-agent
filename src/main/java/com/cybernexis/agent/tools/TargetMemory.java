/*
 * Durable per-host notes and a Token Map. Survives tasks and Burp restarts
 * (Burp preferences). Task {{variables}} stay ephemeral; this store keeps
 * login paths, CSRF field names, cookie names, and where JWT/UUID/API keys
 * were seen so a new chat on the same host does not start from zero.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import com.cybernexis.agent.json.Json;

public final class TargetMemory {

    public static final String PREFS_KEY = "com.cybernexis.agent.target_memory";

    static final int MAX_FACTS = 40;
    static final int MAX_TOKENS = 30;
    static final int MAX_VALUE = 4096;

    public static final class Token {
        public final int id;
        public final String kind;
        public final String name;
        public final String where;
        public final String value;
        public final long updated;

        Token(int id, String kind, String name, String where, String value, long updated) {
            this.id = id;
            this.kind = kind;
            this.name = name;
            this.where = where;
            this.value = value;
            this.updated = updated;
        }
    }

    private static final class HostEntry {
        final LinkedHashMap<String, String> facts = new LinkedHashMap<>();
        final List<Token> tokens = new ArrayList<>();
    }

    private final Map<String, HostEntry> hosts = new LinkedHashMap<>();
    private int nextTokenId = 1;
    private Consumer<String> persist = json -> {
    };

    public TargetMemory() {
    }

    public TargetMemory onPersist(Consumer<String> persist) {
        this.persist = persist == null ? json -> {
        } : persist;
        return this;
    }

    public static TargetMemory load(burp.api.montoya.persistence.Preferences prefs) {
        TargetMemory memory = fromJson(prefs == null ? null : prefs.getString(PREFS_KEY));
        if (prefs != null) {
            memory.onPersist(json -> prefs.setString(PREFS_KEY, json));
        }
        return memory;
    }

    public synchronized boolean isEmpty() {
        return hosts.isEmpty();
    }

    public synchronized boolean hasHost(String host) {
        HostEntry e = hosts.get(Focus.normalize(host));
        return e != null && (!e.facts.isEmpty() || !e.tokens.isEmpty());
    }

    public synchronized int factCount(String host) {
        HostEntry e = hosts.get(Focus.normalize(host));
        return e == null ? 0 : e.facts.size();
    }

    public synchronized int tokenCount(String host) {
        HostEntry e = hosts.get(Focus.normalize(host));
        return e == null ? 0 : e.tokens.size();
    }

    /** Store or replace a fact. Returns the normalized host, or null if rejected. */
    public synchronized String remember(String host, String key, String value, boolean append) {
        String h = Focus.normalize(host);
        String k = normalizeKey(key);
        if (h == null || k == null || value == null) {
            return null;
        }
        String v = clipStore(value);
        HostEntry e = hosts.computeIfAbsent(h, x -> new HostEntry());
        if (append && e.facts.containsKey(k)) {
            String prev = e.facts.get(k);
            if (prev != null && !prev.isEmpty() && !prev.contains(v)) {
                v = clipStore(prev + "; " + v);
            }
        }
        if (!e.facts.containsKey(k) && e.facts.size() >= MAX_FACTS) {
            Iterator<String> it = e.facts.keySet().iterator();
            if (it.hasNext()) {
                it.next();
                it.remove();
            }
        }
        e.facts.put(k, v);
        save();
        return h;
    }

    public synchronized String forgetFact(String host, String key) {
        String h = Focus.normalize(host);
        String k = normalizeKey(key);
        HostEntry e = hosts.get(h);
        if (e == null || k == null || !e.facts.containsKey(k)) {
            return null;
        }
        e.facts.remove(k);
        dropIfEmpty(h, e);
        save();
        return h;
    }

    public synchronized Token forgetToken(int id) {
        for (Map.Entry<String, HostEntry> he : hosts.entrySet()) {
            Iterator<Token> it = he.getValue().tokens.iterator();
            while (it.hasNext()) {
                Token t = it.next();
                if (t.id == id) {
                    it.remove();
                    dropIfEmpty(he.getKey(), he.getValue());
                    save();
                    return t;
                }
            }
        }
        return null;
    }

    public synchronized boolean wipeHost(String host) {
        String h = Focus.normalize(host);
        if (h == null || hosts.remove(h) == null) {
            return false;
        }
        save();
        return true;
    }

    public synchronized boolean clearTokens(String host) {
        String h = Focus.normalize(host);
        HostEntry e = hosts.get(h);
        if (e == null || e.tokens.isEmpty()) {
            return false;
        }
        e.tokens.clear();
        dropIfEmpty(h, e);
        save();
        return true;
    }

    /**
     * Insert or refresh a token (same kind+name+where updates the value).
     * Returns the stored token, or null if host/kind is missing.
     */
    public synchronized Token putToken(String host, String kind, String name, String where, String value) {
        String h = Focus.normalize(host);
        String k = kind == null ? null : kind.trim().toLowerCase();
        if (h == null || k == null || k.isEmpty()) {
            return null;
        }
        String n = name == null || name.isEmpty() ? k : name.trim();
        String w = where == null ? "" : where.trim();
        String v = clipStore(value == null ? "" : value);
        HostEntry e = hosts.computeIfAbsent(h, x -> new HostEntry());
        for (int i = 0; i < e.tokens.size(); i++) {
            Token t = e.tokens.get(i);
            if (t.kind.equals(k) && t.name.equalsIgnoreCase(n) && t.where.equalsIgnoreCase(w)) {
                Token updated = new Token(t.id, k, n, w, v, System.currentTimeMillis());
                e.tokens.set(i, updated);
                save();
                return updated;
            }
        }
        while (e.tokens.size() >= MAX_TOKENS) {
            e.tokens.remove(0);
        }
        Token created = new Token(nextTokenId++, k, n, w, v, System.currentTimeMillis());
        e.tokens.add(created);
        save();
        return created;
    }

    /**
     * After extract_from_response: record the live value in the Token Map and,
     * for csrf/jwt/cookie, fill missing durable field/cookie facts.
     */
    public synchronized void recordExtract(String host, String varName, String how, String value, String cookieName) {
        String h = Focus.normalize(host);
        if (h == null) {
            return;
        }
        String kind = kindFromHow(how);
        String name = varName == null ? kind : varName;
        String where = how == null ? "extract" : how;
        if ("cookie".equals(kind) && cookieName != null && !cookieName.isEmpty()) {
            name = cookieName;
            rememberIfAbsent(h, "session_cookie", cookieName);
        } else if ("csrf".equals(kind)) {
            String field = guessCsrfField(how, varName);
            if (field != null) {
                rememberIfAbsent(h, "csrf_field", field);
            }
        } else if ("jwt".equals(kind)) {
            rememberIfAbsent(h, "auth_scheme", "jwt");
        }
        putToken(h, kind, name, where, value);
    }

    public synchronized Map<String, String> facts(String host) {
        HostEntry e = hosts.get(Focus.normalize(host));
        return e == null ? new LinkedHashMap<>() : new LinkedHashMap<>(e.facts);
    }

    public synchronized List<Token> tokens(String host) {
        HostEntry e = hosts.get(Focus.normalize(host));
        return e == null ? new ArrayList<>() : new ArrayList<>(e.tokens);
    }

    public synchronized List<String> rememberedHosts() {
        return new ArrayList<>(hosts.keySet());
    }

    /** Compact block for the agent CURRENT STATE. */
    public synchronized String promptBlock(String focusHost) {
        StringBuilder sb = new StringBuilder();
        String focus = Focus.normalize(focusHost);
        if (focus != null) {
            HostEntry e = hosts.get(focus);
            if (e == null || (e.facts.isEmpty() && e.tokens.isEmpty())) {
                sb.append("- Target memory: none for ").append(focus)
                  .append(". After mapping login/CSRF/cookies/endpoints, call remember so the next task starts with them.\n");
                return sb.toString();
            }
            sb.append("- Target memory for ").append(focus)
              .append(" (durable across tasks; field names/paths persist, token VALUES expire):\n");
            appendHost(sb, e, "    ");
            return sb.toString();
        }
        if (hosts.isEmpty()) {
            sb.append("- Target memory: none. remember facts per host after recon.\n");
            return sb.toString();
        }
        sb.append("- Target memory hosts:\n");
        int n = 0;
        for (Map.Entry<String, HostEntry> he : hosts.entrySet()) {
            if (n++ >= 12) {
                sb.append("    … ").append(hosts.size() - 12).append(" more\n");
                break;
            }
            HostEntry e = he.getValue();
            sb.append("    ").append(he.getKey()).append(" — ")
              .append(e.facts.size()).append(" facts, ")
              .append(e.tokens.size()).append(" tokens\n");
        }
        sb.append("  Call list_memory with a host (or set a task focus) to see details.\n");
        return sb.toString();
    }

    public synchronized Map<String, Object> snapshotHost(String host) {
        String h = Focus.normalize(host);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("host", h);
        HostEntry e = h == null ? null : hosts.get(h);
        List<Map<String, Object>> factRows = new ArrayList<>();
        List<Map<String, Object>> tokenRows = new ArrayList<>();
        if (e != null) {
            for (Map.Entry<String, String> f : e.facts.entrySet()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("key", f.getKey());
                row.put("value", f.getValue());
                factRows.add(row);
            }
            for (Token t : e.tokens) {
                tokenRows.add(tokenRow(t, true));
            }
        }
        data.put("facts", factRows);
        data.put("tokens", tokenRows);
        data.put("fact_count", factRows.size());
        data.put("token_count", tokenRows.size());
        return data;
    }

    public synchronized Map<String, Object> snapshotSummary() {
        List<Map<String, Object>> items = new ArrayList<>();
        for (Map.Entry<String, HostEntry> he : hosts.entrySet()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("host", he.getKey());
            row.put("fact_count", he.getValue().facts.size());
            row.put("token_count", he.getValue().tokens.size());
            items.add(row);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("hosts", items);
        data.put("host_count", items.size());
        return data;
    }

    public synchronized String toJson() {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("next_token_id", nextTokenId);
        Map<String, Object> hostMap = new LinkedHashMap<>();
        for (Map.Entry<String, HostEntry> he : hosts.entrySet()) {
            Map<String, Object> hm = new LinkedHashMap<>();
            hm.put("facts", new LinkedHashMap<>(he.getValue().facts));
            List<Map<String, Object>> toks = new ArrayList<>();
            for (Token t : he.getValue().tokens) {
                toks.add(tokenRow(t, false));
            }
            hm.put("tokens", toks);
            hostMap.put(he.getKey(), hm);
        }
        root.put("hosts", hostMap);
        return Json.write(root);
    }

    public static TargetMemory fromJson(String json) {
        TargetMemory memory = new TargetMemory();
        if (json == null || json.trim().isEmpty()) {
            return memory;
        }
        Map<String, Object> root = Json.parseObject(json);
        memory.nextTokenId = Math.max(1, Json.asInt(root.get("next_token_id"), 1));
        Map<String, Object> hostMap = Json.asMap(root.get("hosts"));
        for (Map.Entry<String, Object> he : hostMap.entrySet()) {
            String host = Focus.normalize(he.getKey());
            if (host == null) {
                continue;
            }
            Map<String, Object> hm = Json.asMap(he.getValue());
            HostEntry e = new HostEntry();
            for (Map.Entry<String, Object> f : Json.asMap(hm.get("facts")).entrySet()) {
                String k = normalizeKey(f.getKey());
                if (k != null && f.getValue() != null) {
                    e.facts.put(k, clipStore(String.valueOf(f.getValue())));
                }
            }
            for (Object item : Json.asList(hm.get("tokens"))) {
                Map<String, Object> tm = Json.asMap(item);
                int id = Json.asInt(tm.get("id"), memory.nextTokenId);
                if (id >= memory.nextTokenId) {
                    memory.nextTokenId = id + 1;
                }
                String kind = Json.asString(tm.get("kind"), "other");
                e.tokens.add(new Token(
                        id,
                        kind,
                        Json.asString(tm.get("name"), kind),
                        Json.asString(tm.get("where"), ""),
                        Json.asString(tm.get("value"), ""),
                        0L));
            }
            if (!e.facts.isEmpty() || !e.tokens.isEmpty()) {
                memory.hosts.put(host, e);
            }
        }
        return memory;
    }

    static String normalizeKey(String key) {
        if (key == null) {
            return null;
        }
        String k = key.trim().toLowerCase().replace('-', '_').replace(' ', '_');
        if (k.isEmpty() || !k.matches("[a-z_][a-z0-9_]*")) {
            return null;
        }
        return k;
    }

    static Map<String, Object> tokenRow(Token t, boolean truncateValue) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", t.id);
        row.put("kind", t.kind);
        row.put("name", t.name);
        row.put("where", t.where);
        row.put("value", truncateValue ? clip(t.value, 120) : t.value);
        if (t.value != null) {
            row.put("length", t.value.length());
        }
        return row;
    }

    private void rememberIfAbsent(String host, String key, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        HostEntry e = hosts.computeIfAbsent(host, x -> new HostEntry());
        if (!e.facts.containsKey(key)) {
            e.facts.put(key, clipStore(value));
        }
    }

    private void dropIfEmpty(String host, HostEntry e) {
        if (e.facts.isEmpty() && e.tokens.isEmpty()) {
            hosts.remove(host);
        }
    }

    private void save() {
        try {
            persist.accept(toJson());
        } catch (RuntimeException ignored) {
        }
    }

    private static void appendHost(StringBuilder sb, HostEntry e, String indent) {
        if (!e.facts.isEmpty()) {
            sb.append(indent).append("facts:\n");
            int n = 0;
            for (Map.Entry<String, String> f : e.facts.entrySet()) {
                if (n++ >= 16) {
                    sb.append(indent).append("  … ").append(e.facts.size() - 16).append(" more\n");
                    break;
                }
                sb.append(indent).append("  ").append(f.getKey()).append(" = ")
                  .append(clip(f.getValue(), 100)).append('\n');
            }
        }
        if (!e.tokens.isEmpty()) {
            sb.append(indent).append("token map (re-extract live values with extract_from_response):\n");
            int n = 0;
            for (Token t : e.tokens) {
                if (n++ >= 10) {
                    sb.append(indent).append("  … ").append(e.tokens.size() - 10).append(" more\n");
                    break;
                }
                sb.append(indent).append("  #").append(t.id).append(' ').append(t.kind)
                  .append(' ').append(t.name);
                if (t.where != null && !t.where.isEmpty()) {
                    sb.append(" @ ").append(clip(t.where, 40));
                }
                if (t.value != null && !t.value.isEmpty()) {
                    sb.append("  ").append(clip(t.value, 48));
                }
                sb.append('\n');
            }
        }
    }

    private static String kindFromHow(String how) {
        if (how == null) {
            return "other";
        }
        String h = how.toLowerCase();
        if (h.contains("csrf")) {
            return "csrf";
        }
        if (h.contains("jwt")) {
            return "jwt";
        }
        if (h.contains("cookie")) {
            return "cookie";
        }
        return "other";
    }

    private static String guessCsrfField(String how, String varName) {
        if (how != null && how.toLowerCase().contains("requestverification")) {
            return "__RequestVerificationToken";
        }
        if (varName != null && !varName.isEmpty()
                && !"csrf".equals(varName) && !"token".equals(varName) && !"xsrf".equals(varName)) {
            return varName;
        }
        return null;
    }

    static String clip(String s, int max) {
        if (s == null) {
            return "";
        }
        String t = s.replace('\r', ' ').replace('\n', ' ').trim();
        if (t.length() <= max) {
            return t;
        }
        return t.substring(0, max) + "…";
    }

    private static String clipStore(String s) {
        if (s.length() <= MAX_VALUE) {
            return s;
        }
        return s.substring(0, MAX_VALUE);
    }
}
