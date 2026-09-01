/*
 * Shared helpers for tool executors: argument coercion, message-store lookups,
 * and compact summaries of Burp HTTP messages and issues.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.cybernexis.agent.json.Json;

public final class Tools {

    private Tools() {
    }

    // ---- Argument helpers ---------------------------------------------------

    public static String str(Map<String, Object> args, String key) {
        Object v = args.get(key);
        return v == null ? null : String.valueOf(v);
    }

    public static String str(Map<String, Object> args, String key, String def) {
        String v = str(args, key);
        return v == null || v.isEmpty() ? def : v;
    }

    public static Integer intOrNull(Map<String, Object> args, String key) {
        Object v = args.get(key);
        if (v instanceof Number) {
            return ((Number) v).intValue();
        }
        if (v instanceof String) {
            try {
                return (int) Double.parseDouble((String) v);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    public static int intOr(Map<String, Object> args, String key, int def) {
        Integer v = intOrNull(args, key);
        return v == null ? def : v;
    }

    public static boolean boolOr(Map<String, Object> args, String key, boolean def) {
        return Json.asBool(args.get(key), def);
    }

    public static List<String> strList(Map<String, Object> args, String key) {
        return Json.asStringList(args.get(key));
    }

    public static List<Integer> intList(Map<String, Object> args, String key) {
        List<Integer> out = new ArrayList<>();
        Object v = args.get(key);
        if (v instanceof List) {
            for (Object item : (List<?>) v) {
                if (item instanceof Number) {
                    out.add(((Number) item).intValue());
                } else if (item != null) {
                    try {
                        out.add((int) Double.parseDouble(String.valueOf(item)));
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        } else if (v instanceof Number) {
            out.add(((Number) v).intValue());
        } else if (v instanceof String) {
            for (String part : ((String) v).split("[,\\s]+")) {
                if (!part.isEmpty()) {
                    try {
                        out.add((int) Double.parseDouble(part));
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        }
        return out;
    }

    // ---- Message summaries --------------------------------------------------

    public static Map<String, Object> summarize(MessageStore.Entry entry) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", entry.id);
        m.put("source", entry.source);
        HttpRequestResponse hrr = entry.message;
        try {
            m.put("method", hrr.request().method());
            m.put("url", hrr.request().url());
        } catch (RuntimeException e) {
            m.put("url", "<malformed>");
        }
        if (hrr.hasResponse() && hrr.response() != null) {
            m.put("status", (int) hrr.response().statusCode());
            m.put("response_length", hrr.response().body().length());
        } else {
            m.put("status", null);
        }
        return m;
    }

    public static Map<String, Object> detail(MessageStore.Entry entry, int maxBody) {
        Map<String, Object> m = summarize(entry);
        HttpRequestResponse hrr = entry.message;
        try {
            m.put("request", truncate(hrr.request().toString(), maxBody));
        } catch (RuntimeException ignored) {
        }
        if (hrr.hasResponse() && hrr.response() != null) {
            m.put("response", truncate(hrr.response().toString(), maxBody));
        }
        return m;
    }

    public static Map<String, Object> summarizeIssue(int id, AuditIssue issue) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issue_id", id);
        m.put("name", issue.name());
        m.put("severity", issue.severity() == null ? null : issue.severity().name());
        m.put("confidence", issue.confidence() == null ? null : issue.confidence().name());
        m.put("base_url", issue.baseUrl());
        return m;
    }

    public static Map<String, Object> detailIssue(int id, AuditIssue issue, int maxBody) {
        Map<String, Object> m = summarizeIssue(id, issue);
        m.put("detail", truncate(issue.detail(), maxBody));
        m.put("remediation", truncate(issue.remediation(), maxBody));
        List<Map<String, Object>> evidence = new ArrayList<>();
        for (HttpRequestResponse hrr : issue.requestResponses()) {
            Map<String, Object> e = new LinkedHashMap<>();
            try {
                e.put("url", hrr.request().url());
            } catch (RuntimeException ignored) {
            }
            if (hrr.hasResponse() && hrr.response() != null) {
                e.put("status", (int) hrr.response().statusCode());
            }
            evidence.add(e);
        }
        m.put("evidence", evidence);
        return m;
    }

    // ---- Request building ---------------------------------------------------

    /** Resolve a request from a stored id (edits applied) or a fresh url/host. */
    public static HttpRequest resolveRequest(Map<String, Object> args, ToolContext ctx) {
        Integer requestId = intOrNull(args, "request_id");
        HttpRequest request = null;
        if (requestId != null) {
            MessageStore.Entry entry = ctx.messages.get(requestId);
            if (entry != null) {
                request = entry.message.request();
            }
        }
        if (request == null) {
            String url = interp(ctx, str(args, "url"));
            if (url != null) {
                request = HttpRequest.httpRequestFromUrl(url);
            }
        }
        if (request == null) {
            String host = interp(ctx, str(args, "host"));
            if (host != null) {
                boolean secure = host.startsWith("https") || boolOr(args, "secure", true);
                request = HttpRequest.httpRequestFromUrl(
                        (secure ? "https://" : "http://") + host.replaceFirst("^https?://", ""));
            }
        }
        if (request == null) {
            return null;
        }
        request = expandPlaceholders(request, ctx);
        // Apply simple header/method/body edits if provided.
        String method = interp(ctx, str(args, "method"));
        if (method != null) {
            request = request.withMethod(method);
        }
        Object edits = args.get("edits");
        if (edits instanceof List) {
            for (Object editObj : (List<?>) edits) {
                request = applyEdit(request, Json.asMap(editObj), ctx);
            }
        }
        return request;
    }

    /**
     * Apply one edit to a request, tolerating the shapes models actually emit:
     * {"type":"header","name":N,"value":V}, {"header":N,"value":V}, {"name":N,"value":V},
     * plus {"path":V}, {"body":V}, {"method":V} shorthands. Missing headers are added.
     */
    private static HttpRequest applyEdit(HttpRequest request, Map<String, Object> edit, ToolContext ctx) {
        if (edit == null || edit.isEmpty()) {
            return request;
        }
        String type = str(edit, "type");

        // Shorthand keys where the key names the field being edited.
        String pathShort = interp(ctx, str(edit, "path"));
        if ((type == null || type.equalsIgnoreCase("path")) && pathShort != null && !edit.containsKey("value")) {
            return request.withPath(pathShort);
        }
        String bodyShort = interp(ctx, str(edit, "body"));
        if ((type == null || type.equalsIgnoreCase("body")) && bodyShort != null && !edit.containsKey("value")) {
            return request.withBody(bodyShort);
        }
        String methodShort = interp(ctx, str(edit, "method"));
        if ((type == null || type.equalsIgnoreCase("method")) && methodShort != null && !edit.containsKey("value")) {
            return request.withMethod(methodShort);
        }

        // Header name can arrive as name / header / key.
        String headerName = interp(ctx, str(edit, "name"));
        if (headerName == null) {
            headerName = interp(ctx, str(edit, "header"));
        }
        if (headerName == null) {
            headerName = interp(ctx, str(edit, "key"));
        }
        String value = interp(ctx, str(edit, "value", ""));

        if (type == null) {
            type = headerName != null ? "header" : null;
        }
        if (type == null) {
            return request;
        }
        switch (type.toLowerCase()) {
            case "header":
                if (headerName != null) {
                    request = request.hasHeader(headerName)
                            ? request.withUpdatedHeader(headerName, value)
                            : request.withAddedHeader(headerName, value);
                }
                return request;
            case "body":
                return request.withBody(value);
            case "path":
                return value.isEmpty() ? request : request.withPath(value);
            case "method":
                return value.isEmpty() ? request : request.withMethod(value);
            default:
                return request;
        }
    }

    private static HttpRequest expandPlaceholders(HttpRequest request, ToolContext ctx) {
        if (request == null || ctx == null) {
            return request;
        }
        try {
            String raw = request.toString();
            if (raw == null || !raw.contains("{{")) {
                return request;
            }
            String expanded = ctx.vars().interpolate(raw);
            if (expanded.equals(raw)) {
                return request;
            }
            return HttpRequest.httpRequest(request.httpService(), expanded);
        } catch (RuntimeException e) {
            return request;
        }
    }

    /** Expand {{name}} placeholders using this task's variable store. */
    public static String interp(ToolContext ctx, String s) {
        if (s == null || ctx == null) {
            return s;
        }
        return ctx.vars().interpolate(s);
    }

    public static String truncate(String s, int max) {
        if (s == null) {
            return null;
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "\n...[truncated " + (s.length() - max) + " chars]";
    }
}
