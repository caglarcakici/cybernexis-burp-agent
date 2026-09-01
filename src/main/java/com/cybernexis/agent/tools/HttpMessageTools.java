/*
 * HTTP message tools: search stored messages, inspect one by id, list proxy
 * history, send a request, and hand messages off to other Burp tools.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public final class HttpMessageTools {

    private static final int DETAIL_MAX_BODY = 6000;

    private HttpMessageTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "search_http_messages",
                "Search stored HTTP messages by Java regex. args: pattern (required), kind (request|response|both), max_results?, case_insensitive?.",
                false,
                Schema.object()
                        .prop("pattern", "string", "Java regular expression.")
                        .prop("kind", "string", "request | response | both (default both).")
                        .prop("max_results", "integer", "Maximum matches to return (default 50).")
                        .prop("case_insensitive", "boolean", "Case-insensitive match (default false).")
                        .require("pattern")
                        .build(),
                HttpMessageTools::search));

        registry.register(new ToolDescriptor(
                "inspect_http_message",
                "Get a stored HTTP message (request and response) by message_id. args: message_id (required).",
                false,
                Schema.object().prop("message_id", "integer", "Id from search/list results.").require("message_id").build(),
                HttpMessageTools::inspect));

        registry.register(new ToolDescriptor(
                "list_proxy_history",
                "List recent proxy history entries with their ids. args: max_results?, url_contains?.",
                false,
                Schema.object()
                        .prop("max_results", "integer", "Maximum entries (default 100).")
                        .prop("url_contains", "string", "Filter by URL substring.")
                        .build(),
                HttpMessageTools::proxyHistory));

        registry.register(new ToolDescriptor(
                "send_request",
                "Send a new request (url or host) or a stored request (request_id) with optional edits[]. Sends live traffic. "
                        + "Each edit sets one field; headers are ADDED if absent, otherwise updated. Accepted edit shapes: "
                        + "{\"type\":\"header\",\"name\":\"X-Token\",\"value\":\"v\"} or the shorthand {\"header\":\"X-Token\",\"value\":\"v\"}; "
                        + "also {\"type\":\"path\",\"value\":\"/x\"}, {\"type\":\"body\",\"value\":\"...\"}, {\"type\":\"method\",\"value\":\"POST\"}. "
                        + "args: url|host|request_id, method?, edits[]?.",
                true,
                Schema.object()
                        .prop("url", "string", "Full URL for a new request.")
                        .prop("host", "string", "Host for a new request (used with method/edits).")
                        .prop("request_id", "integer", "Id of a stored request to resend.")
                        .prop("method", "string", "Override HTTP method.")
                        .arrayProp("edits", "object", "List of {type:header|body|path, name?, value}.")
                        .build(),
                HttpMessageTools::sendRequest));

        registry.register(new ToolDescriptor(
                "send_to",
                "Send stored requests to another Burp tool. args: request_ids[] (required), destination (repeater|intruder|organizer|comparer).",
                true,
                Schema.object()
                        .arrayProp("request_ids", "integer", "Stored message ids.")
                        .prop("destination", "string", "repeater | intruder | organizer | comparer.")
                        .require("request_ids", "destination")
                        .build(),
                HttpMessageTools::sendTo));
    }

    private static ToolResult search(Map<String, Object> args, ToolContext ctx) {
        String pattern = Tools.str(args, "pattern");
        if (pattern == null || pattern.isEmpty()) {
            return ToolResult.error("pattern is required.");
        }
        String kind = Tools.str(args, "kind", "both").toLowerCase();
        int limit = Tools.intOr(args, "max_results", 50);
        boolean ci = Tools.boolOr(args, "case_insensitive", false);
        Pattern regex;
        try {
            regex = Pattern.compile(pattern, ci ? Pattern.CASE_INSENSITIVE : 0);
        } catch (RuntimeException e) {
            return ToolResult.error("Invalid regex: " + e.getMessage());
        }

        ctx.messages.refresh(ctx.api);
        List<Map<String, Object>> matches = new ArrayList<>();
        int total = 0;
        for (MessageStore.Entry entry : ctx.messages.all()) {
            boolean hit = false;
            HttpRequestResponse hrr = entry.message;
            try {
                if (!kind.equals("response")) {
                    hit = regex.matcher(hrr.request().toString()).find();
                }
                if (!hit && !kind.equals("request") && hrr.hasResponse() && hrr.response() != null) {
                    hit = regex.matcher(hrr.response().toString()).find();
                }
            } catch (RuntimeException ignored) {
            }
            if (hit) {
                if (ctx.focusHost() != null) {
                    try {
                        if (!Focus.urlMatches(hrr.request().url(), ctx.focusHost())) {
                            continue;
                        }
                    } catch (RuntimeException e) {
                        continue;
                    }
                }
                total++;
                if (matches.size() < limit) {
                    matches.add(Tools.summarize(entry));
                }
            }
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("total_matched", total);
        data.put("returned", matches.size());
        data.put("matches", matches);
        return ToolResult.ok(data);
    }

    private static ToolResult inspect(Map<String, Object> args, ToolContext ctx) {
        Integer id = Tools.intOrNull(args, "message_id");
        if (id == null) {
            return ToolResult.error("message_id is required.");
        }
        ctx.messages.refresh(ctx.api);
        MessageStore.Entry entry = ctx.messages.get(id);
        if (entry == null) {
            return ToolResult.error("No stored message with id " + id + ".");
        }
        return ToolResult.ok(Tools.detail(entry, DETAIL_MAX_BODY));
    }

    private static ToolResult proxyHistory(Map<String, Object> args, ToolContext ctx) {
        int limit = Tools.intOr(args, "max_results", 100);
        String filter = Tools.str(args, "url_contains");
        List<ProxyHttpRequestResponse> history;
        try {
            history = ctx.api.proxy().history();
        } catch (RuntimeException e) {
            return ToolResult.error("Proxy history unavailable: " + e.getMessage());
        }
        ctx.messages.refresh(ctx.api);
        List<Map<String, Object>> items = new ArrayList<>();
        int total = 0;
        for (int i = history.size() - 1; i >= 0; i--) {
            ProxyHttpRequestResponse phrr = history.get(i);
            String url;
            try {
                url = phrr.finalRequest().url();
            } catch (RuntimeException e) {
                continue;
            }
            if (ctx.focusHost() != null && !Focus.urlMatches(url, ctx.focusHost())) {
                continue;
            }
            if (filter != null && !url.toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }
            total++;
            if (items.size() >= limit) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", phrr.id());
            try {
                m.put("method", phrr.finalRequest().method());
            } catch (RuntimeException ignored) {
            }
            m.put("url", url);
            m.put("status", phrr.hasResponse() ? (int) phrr.response().statusCode() : null);
            items.add(m);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("total_matched", total);
        data.put("returned", items.size());
        data.put("items", items);
        return ToolResult.ok(data);
    }

    private static ToolResult sendRequest(Map<String, Object> args, ToolContext ctx) {
        HttpRequest request = Tools.resolveRequest(args, ctx);
        if (request == null) {
            return ToolResult.error("Provide url, host, or a valid request_id.");
        }
        HttpRequestResponse result;
        try {
            result = ctx.api.http().sendRequest(request);
        } catch (RuntimeException e) {
            return ToolResult.error("send failed: " + e.getMessage());
        }
        int id = ctx.messages.register(result, "sent");
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("message_id", id);
        try {
            data.put("url", result.request().url());
        } catch (RuntimeException ignored) {
        }
        if (result.hasResponse() && result.response() != null) {
            data.put("status", (int) result.response().statusCode());
            data.put("response_length", result.response().body().length());
            data.put("response_preview", Tools.truncate(result.response().toString(), 2000));
        } else {
            data.put("status", null);
            data.put("note", "No response received.");
        }
        return ToolResult.ok(data);
    }

    private static ToolResult sendTo(Map<String, Object> args, ToolContext ctx) {
        List<Integer> ids = Tools.intList(args, "request_ids");
        String destination = Tools.str(args, "destination", "").toLowerCase();
        if (ids.isEmpty()) {
            return ToolResult.error("request_ids is required.");
        }
        if (destination.equals("sequencer")) {
            return ToolResult.error("The Montoya API does not expose sending to Sequencer; not supported.");
        }
        ctx.messages.refresh(ctx.api);
        List<Object> results = new ArrayList<>();
        for (int id : ids) {
            MessageStore.Entry entry = ctx.messages.get(id);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("request_id", id);
            if (entry == null) {
                r.put("ok", false);
                r.put("error", "no such message id");
                results.add(r);
                continue;
            }
            try {
                HttpRequestResponse hrr = entry.message;
                HttpRequest req = hrr.request();
                switch (destination) {
                    case "repeater":
                        ctx.api.repeater().sendToRepeater(req);
                        break;
                    case "intruder":
                        ctx.api.intruder().sendToIntruder(req);
                        break;
                    case "organizer":
                        ctx.api.organizer().sendToOrganizer(hrr);
                        break;
                    case "comparer":
                        ctx.api.comparer().sendToComparer(req.toByteArray());
                        if (hrr.hasResponse() && hrr.response() != null) {
                            ByteArray respBytes = hrr.response().toByteArray();
                            ctx.api.comparer().sendToComparer(respBytes);
                        }
                        break;
                    default:
                        r.put("ok", false);
                        r.put("error", "unknown destination '" + destination + "'");
                        results.add(r);
                        continue;
                }
                r.put("ok", true);
            } catch (RuntimeException e) {
                r.put("ok", false);
                r.put("error", e.getMessage());
            }
            results.add(r);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("destination", destination);
        data.put("results", results);
        return ToolResult.ok(data);
    }
}
