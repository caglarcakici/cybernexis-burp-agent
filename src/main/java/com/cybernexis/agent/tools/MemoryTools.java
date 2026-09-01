/*
 * Per-host durable memory: remember facts (login_path, csrf_field, notes),
 * list/forget them, and scan a stored HTTP message into the Token Map.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.http.message.HttpRequestResponse;

public final class MemoryTools {

    private MemoryTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "remember",
                "Store a durable fact about a host (survives this task and Burp restart). "
                        + "Use for login_path, csrf_field, session_cookie, tech, notes, interesting endpoints — "
                        + "NOT live CSRF/JWT values (those go in extract_from_response / {{vars}}). "
                        + "host defaults to the task focus host. append=true concatenates onto an existing value "
                        + "(useful for notes). args: key, value, host?, append?.",
                false,
                Schema.object()
                        .prop("key", "string", "Fact name: login_path | csrf_field | session_cookie | notes | tech | …")
                        .prop("value", "string", "Fact value (path, field name, short note).")
                        .prop("host", "string", "Host to attach to (default: task focus).")
                        .prop("append", "boolean", "If true, append to the existing value.")
                        .require("key", "value")
                        .build(),
                MemoryTools::remember));

        registry.register(new ToolDescriptor(
                "list_memory",
                "List durable target memory and the Token Map. With a focus host (or host arg) "
                        + "returns facts+tokens for that host; otherwise a summary of remembered hosts. args: host?.",
                false,
                Schema.object()
                        .prop("host", "string", "Host to inspect (default: task focus; omit for all hosts).")
                        .build(),
                MemoryTools::listMemory));

        registry.register(new ToolDescriptor(
                "forget_memory",
                "Delete target memory. Pass key to drop one fact, token_id to drop one Token Map entry, "
                        + "clear_tokens=true to drop all tokens for the host, wipe=true to delete the whole host. "
                        + "args: host?, key?, token_id?, clear_tokens?, wipe?.",
                false,
                Schema.object()
                        .prop("host", "string", "Host (default: task focus).")
                        .prop("key", "string", "Fact key to delete.")
                        .prop("token_id", "integer", "Token Map id from list_memory / scan_tokens.")
                        .prop("clear_tokens", "boolean", "Drop every token for this host.")
                        .prop("wipe", "boolean", "Delete all facts and tokens for this host.")
                        .build(),
                MemoryTools::forget));

        registry.register(new ToolDescriptor(
                "scan_tokens",
                "Scan a stored HTTP message for JWTs, UUIDs, API keys, CSRF fields, and session cookies. "
                        + "Writes hits into the host Token Map and fills missing facts (login_path, csrf_field, "
                        + "session_cookie) without overwriting ones you already remembered. "
                        + "Live values expire — use extract_from_response before sending. "
                        + "args: message_id (required), host?.",
                false,
                Schema.object()
                        .prop("message_id", "integer", "Stored message id (inspect/send/context-menu).")
                        .prop("host", "string", "Override host (default: message URL, else task focus).")
                        .require("message_id")
                        .build(),
                MemoryTools::scanTokens));
    }

    private static ToolResult remember(Map<String, Object> args, ToolContext ctx) {
        String key = Tools.str(args, "key");
        String value = Tools.str(args, "value");
        if (key == null || key.isEmpty()) {
            return ToolResult.error("key is required (e.g. login_path, csrf_field, notes).");
        }
        if (TargetMemory.normalizeKey(key) == null) {
            return ToolResult.error("key must be letters, digits, underscore (e.g. login_path).");
        }
        if (value == null || value.isEmpty()) {
            return ToolResult.error("value is required.");
        }
        String host = resolveHost(args, ctx, null);
        if (host == null) {
            return ToolResult.error("No host. Pass host= or name a URL in this task so it has a focus host.");
        }
        boolean append = Tools.boolOr(args, "append", false);
        ctx.memory().remember(host, key, value, append);
        Map<String, Object> data = ctx.memory().snapshotHost(host);
        data.put("saved", TargetMemory.normalizeKey(key));
        data.put("note", "This fact is visible to every future task on " + host + ".");
        return ToolResult.ok(data);
    }

    private static ToolResult listMemory(Map<String, Object> args, ToolContext ctx) {
        String requested = Tools.str(args, "host");
        String host = requested != null && !requested.isEmpty()
                ? Focus.normalize(requested)
                : ctx.focusHost();
        if (host != null) {
            Map<String, Object> data = ctx.memory().snapshotHost(host);
            data.put("note", "Facts persist. Token VALUES expire — extract_from_response before reuse.");
            return ToolResult.ok(data);
        }
        return ToolResult.ok(ctx.memory().snapshotSummary());
    }

    private static ToolResult forget(Map<String, Object> args, ToolContext ctx) {
        Integer tokenId = Tools.intOrNull(args, "token_id");
        boolean wipe = Tools.boolOr(args, "wipe", false);
        boolean clearTokens = Tools.boolOr(args, "clear_tokens", false);
        String key = Tools.str(args, "key");

        if (tokenId != null) {
            TargetMemory.Token t = ctx.memory().forgetToken(tokenId);
            if (t == null) {
                return ToolResult.error("No token with id " + tokenId + ".");
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("forgotten_token_id", tokenId);
            data.put("kind", t.kind);
            data.put("name", t.name);
            return ToolResult.ok(data);
        }

        String host = resolveHost(args, ctx, null);
        if (host == null) {
            return ToolResult.error("No host. Pass host= or use a focused task.");
        }
        if (wipe) {
            if (!ctx.memory().wipeHost(host)) {
                return ToolResult.error("No memory stored for " + host + ".");
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("wiped_host", host);
            return ToolResult.ok(data);
        }
        if (clearTokens) {
            ctx.memory().clearTokens(host);
            return ToolResult.ok(ctx.memory().snapshotHost(host));
        }
        if (key != null && !key.isEmpty()) {
            if (ctx.memory().forgetFact(host, key) == null) {
                return ToolResult.error("No fact '" + key + "' on " + host + ".");
            }
            return ToolResult.ok(ctx.memory().snapshotHost(host));
        }
        return ToolResult.error("Pass key, token_id, clear_tokens=true, or wipe=true.");
    }

    private static ToolResult scanTokens(Map<String, Object> args, ToolContext ctx) {
        Integer id = Tools.intOrNull(args, "message_id");
        if (id == null) {
            return ToolResult.error("message_id is required.");
        }
        ctx.messages.refresh(ctx.api);
        MessageStore.Entry entry = ctx.messages.get(id);
        if (entry == null) {
            return ToolResult.error("No stored message with id " + id + ".");
        }
        HttpRequestResponse hrr = entry.message;
        String host = resolveHost(args, ctx, hrr);
        if (host == null) {
            return ToolResult.error("Could not determine host from the message. Pass host=.");
        }

        String req = "";
        String res = "";
        try {
            req = hrr.request().toString();
        } catch (RuntimeException ignored) {
        }
        try {
            if (hrr.hasResponse() && hrr.response() != null) {
                res = hrr.response().toString();
            }
        } catch (RuntimeException ignored) {
        }

        List<TokenScanner.Hit> hits = TokenScanner.scan(req, res);
        List<Map<String, Object>> added = new ArrayList<>();
        TargetMemory mem = ctx.memory();
        for (TokenScanner.Hit hit : hits) {
            if (hit.factKey != null && hit.factValue != null
                    && mem.facts(host).get(hit.factKey) == null) {
                mem.remember(host, hit.factKey, hit.factValue, false);
            }
            if ("path".equals(hit.kind)) {
                continue;
            }
            TargetMemory.Token t = mem.putToken(host, hit.kind, hit.name, hit.where, hit.value);
            if (t != null) {
                added.add(TargetMemory.tokenRow(t, true));
            }
        }
        Map<String, Object> data = mem.snapshotHost(host);
        data.put("scanned_message_id", id);
        data.put("hits_this_scan", added.size());
        data.put("new_or_updated", added);
        data.put("note", "Facts are durable. Re-extract live token values before sending requests.");
        return ToolResult.ok(data);
    }

    static String resolveHost(Map<String, Object> args, ToolContext ctx, HttpRequestResponse hrr) {
        String explicit = Focus.normalize(Tools.str(args, "host"));
        if (explicit != null) {
            return explicit;
        }
        if (ctx.focusHost() != null) {
            return ctx.focusHost();
        }
        if (hrr != null) {
            try {
                return Focus.hostOf(hrr.request().url());
            } catch (RuntimeException ignored) {
            }
        }
        return null;
    }
}
