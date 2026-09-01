/*
 * Compare two stored HTTP messages section-by-section. Noisy response headers
 * (dates, request/trace ids, cache/CDN markers) are suppressed so real
 * differences stand out.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public final class CompareTools {

    private static final Set<String> NOISE_HEADERS = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

    static {
        for (String h : new String[]{
                "Date", "Expires", "Age", "Via", "X-Request-Id", "X-Trace-Id",
                "X-Correlation-Id", "X-Amzn-Trace-Id", "CF-Ray", "X-Served-By",
                "X-Cache", "X-Cache-Status", "Server-Timing"}) {
            NOISE_HEADERS.add(h);
        }
    }

    private static final int MAX_BODY_LINES = 200;

    private CompareTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "compare_http_messages",
                "Diff two stored messages section-by-section (headers, status, body). Noise headers auto-suppressed. args: left_message_id (baseline), right_message_id (variant), aspect (request|response|both).",
                false,
                Schema.object()
                        .prop("left_message_id", "integer", "Baseline message id.")
                        .prop("right_message_id", "integer", "Variant message id.")
                        .prop("aspect", "string", "request | response | both (default both).")
                        .require("left_message_id", "right_message_id")
                        .build(),
                CompareTools::compare));
    }

    private static ToolResult compare(Map<String, Object> args, ToolContext ctx) {
        Integer leftId = Tools.intOrNull(args, "left_message_id");
        Integer rightId = Tools.intOrNull(args, "right_message_id");
        if (leftId == null || rightId == null) {
            return ToolResult.error("left_message_id and right_message_id are required.");
        }
        ctx.messages.refresh(ctx.api);
        MessageStore.Entry left = ctx.messages.get(leftId);
        MessageStore.Entry right = ctx.messages.get(rightId);
        if (left == null || right == null) {
            return ToolResult.error("One or both message ids not found.");
        }
        String aspect = Tools.str(args, "aspect", "both").toLowerCase();

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("left_message_id", leftId);
        data.put("right_message_id", rightId);

        if (!aspect.equals("response")) {
            data.put("request", diffRequest(left.message.request(), right.message.request()));
        }
        if (!aspect.equals("request")) {
            data.put("response", diffResponse(left.message, right.message));
        }
        return ToolResult.ok(data);
    }

    private static Map<String, Object> diffRequest(HttpRequest left, HttpRequest right) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            if (!left.method().equals(right.method())) {
                out.put("method", left.method() + " -> " + right.method());
            }
            if (!left.path().equals(right.path())) {
                out.put("path", left.path() + " -> " + right.path());
            }
        } catch (RuntimeException ignored) {
        }
        out.put("headers", diffHeaders(headerMap(left.headers()), headerMap(right.headers())));
        out.put("body", diffBody(safeBody(left), safeBody(right)));
        return out;
    }

    private static Map<String, Object> diffResponse(HttpRequestResponse left, HttpRequestResponse right) {
        Map<String, Object> out = new LinkedHashMap<>();
        HttpResponse l = left.hasResponse() ? left.response() : null;
        HttpResponse r = right.hasResponse() ? right.response() : null;
        if (l == null || r == null) {
            out.put("note", "One or both messages have no response.");
            return out;
        }
        if (l.statusCode() != r.statusCode()) {
            out.put("status_code", l.statusCode() + " -> " + r.statusCode());
        }
        if (l.reasonPhrase() != null && !l.reasonPhrase().equals(r.reasonPhrase())) {
            out.put("reason_phrase", l.reasonPhrase() + " -> " + r.reasonPhrase());
        }
        out.put("headers", diffHeaders(headerMap(l.headers()), headerMap(r.headers())));
        out.put("body", diffBody(l.bodyToString(), r.bodyToString()));
        return out;
    }

    private static Map<String, Object> diffHeaders(Map<String, String> left, Map<String, String> right) {
        List<String> added = new ArrayList<>();
        List<String> removed = new ArrayList<>();
        List<String> changed = new ArrayList<>();
        Set<String> keys = new LinkedHashSet<>();
        keys.addAll(left.keySet());
        keys.addAll(right.keySet());
        for (String k : keys) {
            if (NOISE_HEADERS.contains(k)) {
                continue;
            }
            String lv = left.get(k);
            String rv = right.get(k);
            if (lv == null && rv != null) {
                added.add(k + ": " + rv);
            } else if (lv != null && rv == null) {
                removed.add(k + ": " + lv);
            } else if (lv != null && !lv.equals(rv)) {
                changed.add(k + ": " + lv + " -> " + rv);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("added", added);
        out.put("removed", removed);
        out.put("changed", changed);
        return out;
    }

    private static Map<String, Object> diffBody(String left, String right) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (left.equals(right)) {
            out.put("identical", true);
            return out;
        }
        Set<String> leftLines = new LinkedHashSet<>();
        Set<String> rightLines = new LinkedHashSet<>();
        for (String line : left.split("\n", -1)) {
            leftLines.add(line);
        }
        for (String line : right.split("\n", -1)) {
            rightLines.add(line);
        }
        List<String> onlyLeft = new ArrayList<>();
        for (String line : leftLines) {
            if (!rightLines.contains(line) && onlyLeft.size() < MAX_BODY_LINES) {
                onlyLeft.add(line);
            }
        }
        List<String> onlyRight = new ArrayList<>();
        for (String line : rightLines) {
            if (!leftLines.contains(line) && onlyRight.size() < MAX_BODY_LINES) {
                onlyRight.add(line);
            }
        }
        out.put("identical", false);
        out.put("left_length", left.length());
        out.put("right_length", right.length());
        out.put("removed_lines", onlyLeft);
        out.put("added_lines", onlyRight);
        return out;
    }

    private static Map<String, String> headerMap(List<HttpHeader> headers) {
        Map<String, String> map = new LinkedHashMap<>();
        for (HttpHeader h : headers) {
            map.put(h.name(), h.value());
        }
        return map;
    }

    private static String safeBody(HttpRequest req) {
        try {
            return req.bodyToString();
        } catch (RuntimeException e) {
            return "";
        }
    }
}
