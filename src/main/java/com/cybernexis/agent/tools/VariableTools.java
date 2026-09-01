/*
 * Session variables: extract a value from a stored HTTP message (regex or a
 * CSRF/JWT/cookie preset), set/get/list named vars, then reuse them as {{name}}
 * in send_request / fuzz_request / brute_force edits.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.HttpRequestResponse;

public final class VariableTools {

    private static final String[] CSRF_PATTERNS = {
            "name=[\"']__RequestVerificationToken[\"'][^>]*value=[\"']([^\"']+)[\"']",
            "value=[\"']([^\"']+)[\"'][^>]*name=[\"']__RequestVerificationToken[\"']",
            "name=[\"']_csrf[\"'][^>]*value=[\"']([^\"']+)[\"']",
            "name=[\"']csrf[_-]?token[\"'][^>]*value=[\"']([^\"']+)[\"']",
            "name=[\"']_token[\"'][^>]*value=[\"']([^\"']+)[\"']",
            "(?i)csrf-token[\"']\\s+content=[\"']([^\"']+)[\"']",
            "(?i)\"csrfToken\"\\s*:\\s*\"([^\"]+)\"",
            "(?i)\"csrf_token\"\\s*:\\s*\"([^\"]+)\"",
            "(?i)XSRF-TOKEN=([^;\\s]+)",
            "(?i)RequestVerificationToken=([^;\\s]+)"
    };

    private static final Pattern JWT = Pattern.compile(
            "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

    private VariableTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "extract_from_response",
                "Extract a value from a stored HTTP message and save it as {{name}} for later requests. "
                        + "Use after inspect_http_message / send_request. "
                        + "preset=csrf finds antiforgery / XSRF / meta csrf-token; preset=jwt finds a JWT; "
                        + "preset=cookie plus cookie=<name> reads that cookie. "
                        + "Or pass pattern (Java regex, group 1 by default). "
                        + "Then put {{name}} in send_request/fuzz/brute_force url, body, or header edits. "
                        + "args: message_id (required), name (required), pattern?, group?, kind?, preset?, cookie?.",
                false,
                Schema.object()
                        .prop("message_id", "integer", "Stored message id to read.")
                        .prop("name", "string", "Variable name without braces (e.g. csrf). Refer to it later as {{csrf}}.")
                        .prop("pattern", "string", "Java regex; first capturing group is stored unless group is set.")
                        .prop("group", "integer", "Regex group to store (default 1, or 0 for the full match).")
                        .prop("kind", "string", "response (default) | request | both.")
                        .prop("preset", "string", "csrf | jwt | cookie — used when pattern is omitted.")
                        .prop("cookie", "string", "Cookie name when preset=cookie.")
                        .require("message_id", "name")
                        .build(),
                VariableTools::extract));

        registry.register(new ToolDescriptor(
                "set_variable",
                "Store a named value for this task. Use {{name}} in later send_request/fuzz/brute_force args. args: name, value.",
                false,
                Schema.object()
                        .prop("name", "string", "Variable name without braces.")
                        .prop("value", "string", "Value to store.")
                        .require("name", "value")
                        .build(),
                VariableTools::setVar));

        registry.register(new ToolDescriptor(
                "get_variable",
                "Read a stored task variable. args: name.",
                false,
                Schema.object().prop("name", "string", "Variable name.").require("name").build(),
                VariableTools::getVar));

        registry.register(new ToolDescriptor(
                "list_variables",
                "List this task's stored {{name}} variables (values truncated).",
                false,
                ToolDescriptor.emptyParams(),
                VariableTools::listVars));
    }

    private static ToolResult extract(Map<String, Object> args, ToolContext ctx) {
        Integer id = Tools.intOrNull(args, "message_id");
        String name = VarStore.normalize(Tools.str(args, "name"));
        if (id == null) {
            return ToolResult.error("message_id is required.");
        }
        if (name == null) {
            return ToolResult.error("name is required (letters, digits, underscore; no braces).");
        }
        if (VarStore.RESERVED.contains(name)) {
            return ToolResult.error("'" + name + "' is reserved for brute_force markers ({{pass}}/{{user}}). Pick another name, e.g. csrf.");
        }
        ctx.messages.refresh(ctx.api);
        MessageStore.Entry entry = ctx.messages.get(id);
        if (entry == null) {
            return ToolResult.error("No stored message with id " + id + ".");
        }
        String haystack = haystack(entry.message, Tools.str(args, "kind", "response"));
        if (haystack == null || haystack.isEmpty()) {
            return ToolResult.error("That message has no " + Tools.str(args, "kind", "response") + " body to search.");
        }

        String value;
        String how;
        String preset = Tools.str(args, "preset");
        String pattern = Tools.str(args, "pattern");
        if (pattern != null && !pattern.isEmpty()) {
            int group = Tools.intOr(args, "group", 1);
            value = firstMatch(haystack, pattern, group);
            how = "regex";
        } else if (preset != null) {
            Extracted ex = runPreset(preset, Tools.str(args, "cookie"), haystack, entry.message);
            if (ex == null) {
                return ToolResult.error("preset '" + preset + "' found nothing. Try a custom pattern.");
            }
            value = ex.value;
            how = ex.how;
        } else {
            return ToolResult.error("Provide pattern or preset (csrf | jwt | cookie).");
        }
        if (value == null || value.isEmpty()) {
            return ToolResult.error("No match. Check the regex/preset against inspect_http_message " + id + ".");
        }
        ctx.vars().set(name, value);
        try {
            String host = Focus.hostOf(entry.message.request().url());
            ctx.memory().recordExtract(host, name, how, value, Tools.str(args, "cookie"));
        } catch (RuntimeException ignored) {
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", name);
        data.put("placeholder", "{{" + name + "}}");
        data.put("value", Tools.truncate(value, 240));
        data.put("length", value.length());
        data.put("source_message_id", id);
        data.put("extracted_via", how);
        data.put("note", "Use {{" + name + "}} in send_request/fuzz_request/brute_force url, body, or header values. Field/cookie names are also stored in target memory for this host.");
        return ToolResult.ok(data);
    }

    private static ToolResult setVar(Map<String, Object> args, ToolContext ctx) {
        String name = VarStore.normalize(Tools.str(args, "name"));
        String value = Tools.str(args, "value");
        if (name == null) {
            return ToolResult.error("name is required (letters, digits, underscore).");
        }
        if (VarStore.RESERVED.contains(name)) {
            return ToolResult.error("'" + name + "' is reserved for brute_force ({{pass}}/{{user}}).");
        }
        if (value == null) {
            return ToolResult.error("value is required.");
        }
        ctx.vars().set(name, value);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", name);
        data.put("placeholder", "{{" + name + "}}");
        data.put("value", Tools.truncate(value, 240));
        return ToolResult.ok(data);
    }

    private static ToolResult getVar(Map<String, Object> args, ToolContext ctx) {
        String name = VarStore.normalize(Tools.str(args, "name"));
        if (name == null) {
            return ToolResult.error("name is required.");
        }
        String value = ctx.vars().get(name);
        if (value == null) {
            return ToolResult.error("No variable named '" + name + "'. Call list_variables.");
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", name);
        data.put("placeholder", "{{" + name + "}}");
        data.put("value", value);
        return ToolResult.ok(data);
    }

    private static ToolResult listVars(Map<String, Object> args, ToolContext ctx) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (Map.Entry<String, String> e : ctx.vars().snapshot().entrySet()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", e.getKey());
            row.put("placeholder", "{{" + e.getKey() + "}}");
            row.put("value", Tools.truncate(e.getValue(), 120));
            row.put("length", e.getValue() == null ? 0 : e.getValue().length());
            items.add(row);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("count", items.size());
        data.put("variables", items);
        return ToolResult.ok(data);
    }

    private static String haystack(HttpRequestResponse hrr, String kind) {
        String k = kind == null ? "response" : kind.toLowerCase();
        StringBuilder sb = new StringBuilder();
        try {
            if (!"response".equals(k)) {
                sb.append(hrr.request().toString());
            }
        } catch (RuntimeException ignored) {
        }
        try {
            if (!"request".equals(k) && hrr.hasResponse() && hrr.response() != null) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(hrr.response().toString());
            }
        } catch (RuntimeException ignored) {
        }
        return sb.toString();
    }

    private static String firstMatch(String text, String pattern, int group) {
        try {
            Matcher m = Pattern.compile(pattern).matcher(text);
            if (!m.find()) {
                return null;
            }
            if (group < 0 || group > m.groupCount()) {
                group = m.groupCount() >= 1 ? 1 : 0;
            }
            return m.group(group);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Extracted runPreset(String preset, String cookieName, String haystack,
                                       HttpRequestResponse hrr) {
        switch (preset.trim().toLowerCase()) {
            case "csrf":
            case "xsrf":
            case "antiforgery":
                for (String p : CSRF_PATTERNS) {
                    String v = firstMatch(haystack, p, 1);
                    if (v != null && !v.isEmpty()) {
                        return new Extracted(v, "preset:csrf");
                    }
                }
                return null;
            case "jwt":
            case "token":
                Matcher jwt = JWT.matcher(haystack);
                return jwt.find() ? new Extracted(jwt.group(), "preset:jwt") : null;
            case "cookie":
                if (cookieName == null || cookieName.isEmpty()) {
                    return null;
                }
                String fromSet = firstMatch(haystack,
                        "(?i)(?:^|\\n)set-cookie:\\s*" + Pattern.quote(cookieName) + "=([^;\\r\\n]+)", 1);
                if (fromSet != null) {
                    return new Extracted(fromSet, "preset:cookie Set-Cookie");
                }
                try {
                    String header = hrr.request().headerValue("Cookie");
                    if (header != null) {
                        String fromReq = firstMatch(header,
                                "(?i)(?:^|;\\s*)" + Pattern.quote(cookieName) + "=([^;]+)", 1);
                        if (fromReq != null) {
                            return new Extracted(fromReq.trim(), "preset:cookie request");
                        }
                    }
                } catch (RuntimeException ignored) {
                }
                return null;
            default:
                return null;
        }
    }

    private static final class Extracted {
        final String value;
        final String how;

        Extracted(String value, String how) {
            this.value = value;
            this.how = how;
        }
    }
}
