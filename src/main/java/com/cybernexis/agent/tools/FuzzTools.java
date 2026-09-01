/*
 * Fuzzing tools. fuzz_request actively sends a payload list through Burp's HTTP
 * stack, one request per payload, and analyses each response for timing
 * anomalies (blind SSRF / command injection), payload reflection (XSS), status
 * changes, and error signatures (error-based SQLi / XXE). stage_in_intruder
 * keeps the old behaviour of handing a request to the Intruder UI for manual
 * attacks the Montoya API cannot run programmatically.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.cybernexis.agent.json.Json;

public final class FuzzTools {

    private static final int HARD_MAX = 200;
    private static final int DEFAULT_MAX = 100;
    /** Absolute latency (ms) above which a response is always flagged. */
    private static final int ABSOLUTE_TIMING_MS = 3000;
    /** A slow response must also beat the baseline by this margin to flag. */
    private static final int TIMING_MARGIN_MS = 1000;
    private static final int PAYLOAD_ECHO_MAX = 120;

    /** Substrings that commonly leak from error-based injection / stack traces. */
    private static final String[] ERROR_SIGNATURES = {
            "SQL syntax", "mysql_fetch", "you have an error in your sql",
            "ORA-", "PLS-", "PostgreSQL", "SQLite", "SQLSTATE",
            "unclosed quotation mark", "quoted string not properly terminated",
            "Microsoft OLE DB", "ODBC Driver", "Warning: mysqli",
            "Traceback (most recent call last)", "java.lang.", "java.sql.",
            "System.Data.SqlClient", "org.hibernate", "Uncaught exception",
            "Fatal error", "Stack trace:", "syntax error"
    };

    private FuzzTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "fuzz_request",
                "Actively fuzz one injection point by sending each payload as a live request through Burp and analysing the responses. "
                        + "Pick the base request with request_id | url | host (method/edits[] optional). Choose WHERE to inject with "
                        + "location (query|body|json_body|header|cookie|path) plus parameter=<name>, OR set marker=<token> to replace a "
                        + "literal token you placed anywhere (e.g. body 'id=FUZZ', marker='FUZZ'). mode = replace (default) | append | prepend. "
                        + "Per payload it reports status, response length, duration_ms, payload reflection, error signatures, and a timing_anomaly "
                        + "flag (>3s or >3x baseline) that catches BLIND SSRF and BLIND command injection. Each response is stored so you can "
                        + "inspect_http_message by the returned message_id. args: request_id|url|host, location, parameter?, marker?, payloads[] (required), "
                        + "mode?, max_payloads?, delay_ms?.",
                true,
                Schema.object()
                        .prop("request_id", "integer", "Stored message id to use as the base request.")
                        .prop("url", "string", "URL for a new base request.")
                        .prop("host", "string", "Host for a new base request.")
                        .prop("method", "string", "Override HTTP method on the base request.")
                        .arrayProp("edits", "object", "Optional base-request edits (same shapes as send_request); use to place a marker.")
                        .arrayProp("payloads", "string", "Payload strings to inject, one request each.")
                        .prop("location", "string", "query | body | json_body | header | cookie | path (ignored when marker is set).")
                        .prop("parameter", "string", "Name of the parameter/header/cookie to fuzz (required unless location=path or marker is set).")
                        .prop("marker", "string", "Literal token in the request to replace with each payload; overrides location.")
                        .prop("mode", "string", "replace (default) | append | prepend the payload onto the existing value.")
                        .prop("max_payloads", "integer", "Cap on payloads actually sent (default 100, hard max 200).")
                        .prop("delay_ms", "integer", "Delay between requests in ms (default 0).")
                        .require("payloads")
                        .build(),
                FuzzTools::fuzzRequest));

        registry.register(new ToolDescriptor(
                "stage_in_intruder",
                "Send a request to Intruder for manual fuzzing in the UI (use when you want the analyst to drive the attack). "
                        + "For automated fuzzing with result analysis, prefer fuzz_request. args: request_id | url.",
                true,
                Schema.object()
                        .prop("request_id", "integer", "Stored message id to stage.")
                        .prop("url", "string", "URL for a new request to stage.")
                        .build(),
                FuzzTools::stageInIntruder));
    }

    // ---- Active fuzzer ------------------------------------------------------

    private static ToolResult fuzzRequest(Map<String, Object> args, ToolContext ctx) {
        HttpRequest base = Tools.resolveRequest(args, ctx);
        if (base == null) {
            return ToolResult.error("Provide request_id, url, or host to fuzz.");
        }
        List<String> payloads = new ArrayList<>();
        for (String p : Tools.strList(args, "payloads")) {
            payloads.add(Tools.interp(ctx, p));
        }
        if (payloads.isEmpty()) {
            return ToolResult.error("payloads[] is required: a list of strings to inject.");
        }
        String marker = Tools.str(args, "marker");
        boolean hasMarker = marker != null && !marker.isEmpty();
        String location = Tools.str(args, "location", hasMarker ? "marker" : "query").toLowerCase();
        String parameter = Tools.str(args, "parameter");
        String mode = Tools.str(args, "mode", "replace").toLowerCase();
        int max = Math.min(Tools.intOr(args, "max_payloads", DEFAULT_MAX), HARD_MAX);
        int delay = Math.max(0, Tools.intOr(args, "delay_ms", 0));

        boolean needsParam = location.equals("query") || location.equals("body")
                || location.equals("json_body") || location.equals("header") || location.equals("cookie");
        if (!hasMarker && needsParam && (parameter == null || parameter.isEmpty())) {
            return ToolResult.error("parameter is required for location='" + location
                    + "'. Alternatively set marker to inject at a literal token.");
        }
        if (hasMarker) {
            try {
                if (!base.toString().contains(marker)) {
                    return ToolResult.error("marker '" + marker + "' not found in the request. Place it via edits "
                            + "(e.g. an edit setting body to 'id=" + marker + "') or use location/parameter instead.");
                }
            } catch (RuntimeException ignored) {
            }
        }

        Probe baseline = probe(ctx, base, null);
        if (baseline.error != null && baseline.status == null) {
            return ToolResult.error("Baseline request failed: " + baseline.error);
        }

        int count = Math.min(payloads.size(), max);
        List<Map<String, Object>> rows = new ArrayList<>();
        List<Map<String, Object>> anomalies = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String payload = payloads.get(i);
            HttpRequest req;
            try {
                req = inject(base, location, parameter, hasMarker ? marker : null, mode, payload);
            } catch (RuntimeException e) {
                req = null;
            }
            if (req == null) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("payload", echo(payload));
                row.put("error", "could not inject payload into location '" + location + "'.");
                rows.add(row);
                continue;
            }
            Probe p = probe(ctx, req, payload);
            Map<String, Object> row = analyze(baseline, p, payload);
            rows.add(row);
            if (Boolean.TRUE.equals(row.get("timing_anomaly"))
                    || Boolean.TRUE.equals(row.get("status_changed"))
                    || Boolean.TRUE.equals(row.get("reflected"))
                    || row.get("error_signature") != null) {
                anomalies.add(row);
            }
            if (delay > 0) {
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        Map<String, Object> data = new LinkedHashMap<>();
        try {
            data.put("base_url", base.url());
        } catch (RuntimeException ignored) {
        }
        data.put("injection", hasMarker ? ("marker:" + marker) : (location + (parameter != null ? "[" + parameter + "]" : "")));
        data.put("mode", mode);
        data.put("payloads_sent", rows.size());
        Map<String, Object> baseMap = new LinkedHashMap<>();
        baseMap.put("status", baseline.status);
        baseMap.put("length", baseline.length);
        baseMap.put("duration_ms", baseline.durationMs);
        data.put("baseline", baseMap);
        data.put("anomaly_count", anomalies.size());
        data.put("anomalies", anomalies);
        data.put("results", rows);
        data.put("note", "timing_anomaly flags blind SSRF/command injection; reflected flags possible XSS; "
                + "error_signature flags error-based injection. Use inspect_http_message with a message_id to see full traffic.");
        return ToolResult.ok(data);
    }

    private static Map<String, Object> analyze(Probe baseline, Probe p, String payload) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("payload", echo(payload));
        if (p.error != null && p.status == null) {
            row.put("error", p.error);
            return row;
        }
        row.put("status", p.status);
        row.put("length", p.length);
        row.put("duration_ms", p.durationMs);
        if (p.messageId != null) {
            row.put("message_id", p.messageId);
        }

        boolean timing = p.durationMs >= ABSOLUTE_TIMING_MS
                || (baseline.durationMs > 0
                        && p.durationMs > 3 * baseline.durationMs
                        && p.durationMs - baseline.durationMs >= TIMING_MARGIN_MS);
        row.put("timing_anomaly", timing);

        boolean statusChanged = baseline.status != null && p.status != null
                && !baseline.status.equals(p.status);
        row.put("status_changed", statusChanged);
        row.put("length_delta", p.length - baseline.length);

        boolean reflected = payload != null && payload.length() >= 3
                && p.body != null && p.body.contains(payload);
        row.put("reflected", reflected);

        String sig = errorSignature(p.body);
        if (sig != null) {
            row.put("error_signature", sig);
        }
        return row;
    }

    // ---- Injection ----------------------------------------------------------

    static HttpRequest inject(HttpRequest base, String location, String parameter,
                              String marker, String mode, String payload) {
        if (marker != null) {
            return injectMarker(base, marker, payload);
        }
        switch (location) {
            case "query":
                return withParam(base, HttpParameterType.URL, parameter, mode, payload);
            case "body":
                return withParam(base, HttpParameterType.BODY, parameter, mode, payload);
            case "cookie":
                return withParam(base, HttpParameterType.COOKIE, parameter, mode, payload);
            case "header": {
                String value = combine(base.headerValue(parameter), mode, payload);
                return base.hasHeader(parameter)
                        ? base.withUpdatedHeader(parameter, value)
                        : base.withAddedHeader(parameter, value);
            }
            case "path": {
                String path = base.path();
                String np;
                if ("append".equals(mode)) {
                    np = path + payload;
                } else if ("prepend".equals(mode)) {
                    np = payload + path;
                } else {
                    np = payload;
                }
                return base.withPath(np);
            }
            case "json_body":
                return injectJson(base, parameter, mode, payload);
            default:
                return null;
        }
    }

    static HttpRequest injectMarker(HttpRequest base, String marker, String payload) {
        String raw;
        try {
            raw = base.toString();
        } catch (RuntimeException e) {
            return null;
        }
        if (!raw.contains(marker)) {
            return null;
        }
        HttpService service = base.httpService();
        HttpRequest req = HttpRequest.httpRequest(service, raw.replace(marker, payload));
        // Rebuild the body so Content-Length stays correct when the marker was in it.
        boolean hadBody;
        try {
            hadBody = base.body() != null && base.body().length() > 0;
        } catch (RuntimeException e) {
            hadBody = false;
        }
        if (hadBody) {
            try {
                req = req.withBody(req.bodyToString());
            } catch (RuntimeException ignored) {
            }
        }
        return req;
    }

    private static HttpRequest withParam(HttpRequest base, HttpParameterType type,
                                         String name, String mode, String payload) {
        String value = payload;
        if (!"replace".equals(mode) && base.hasParameter(name, type)) {
            String existing = base.parameterValue(name, type);
            if (existing == null) {
                existing = "";
            }
            value = "prepend".equals(mode) ? payload + existing : existing + payload;
        }
        HttpParameter param;
        switch (type) {
            case URL:
                param = HttpParameter.urlParameter(name, value);
                break;
            case COOKIE:
                param = HttpParameter.cookieParameter(name, value);
                break;
            default:
                param = HttpParameter.bodyParameter(name, value);
        }
        return base.hasParameter(name, type)
                ? base.withUpdatedParameters(param)
                : base.withAddedParameters(param);
    }

    @SuppressWarnings("unchecked")
    private static HttpRequest injectJson(HttpRequest base, String key, String mode, String payload) {
        Object parsed;
        try {
            parsed = Json.parse(base.bodyToString());
        } catch (RuntimeException e) {
            return null;
        }
        if (!(parsed instanceof Map)) {
            return null;
        }
        Map<String, Object> map = (Map<String, Object>) parsed;
        Object value = payload;
        if (!"replace".equals(mode) && map.get(key) != null) {
            String existing = String.valueOf(map.get(key));
            value = "prepend".equals(mode) ? payload + existing : existing + payload;
        }
        map.put(key, value);
        return base.withBody(Json.write(map));
    }

    private static String combine(String existing, String mode, String payload) {
        if ("replace".equals(mode) || existing == null) {
            return payload;
        }
        return "prepend".equals(mode) ? payload + existing : existing + payload;
    }

    // ---- Sending / measuring ------------------------------------------------

    private static Probe probe(ToolContext ctx, HttpRequest req, String payload) {
        Probe out = new Probe();
        long t0 = System.nanoTime();
        HttpRequestResponse rr;
        try {
            rr = ctx.api.http().sendRequest(req);
        } catch (RuntimeException e) {
            out.error = e.getMessage();
            out.durationMs = (System.nanoTime() - t0) / 1_000_000L;
            return out;
        }
        out.durationMs = (System.nanoTime() - t0) / 1_000_000L;
        if (rr.hasResponse() && rr.response() != null) {
            out.status = (int) rr.response().statusCode();
            try {
                out.body = rr.response().bodyToString();
            } catch (RuntimeException ignored) {
                out.body = "";
            }
            out.length = out.body == null ? 0 : out.body.length();
            try {
                out.messageId = ctx.messages.register(rr, payload == null ? "fuzz-baseline" : "fuzz");
            } catch (RuntimeException ignored) {
            }
        } else {
            out.error = "no response";
        }
        return out;
    }

    private static String errorSignature(String body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        String lower = body.toLowerCase();
        for (String sig : ERROR_SIGNATURES) {
            if (lower.contains(sig.toLowerCase())) {
                return sig;
            }
        }
        return null;
    }

    private static String echo(String payload) {
        if (payload == null) {
            return null;
        }
        return payload.length() <= PAYLOAD_ECHO_MAX
                ? payload
                : payload.substring(0, PAYLOAD_ECHO_MAX) + "\u2026";
    }

    private static final class Probe {
        Integer status;
        int length;
        long durationMs;
        String body;
        Integer messageId;
        String error;
    }

    // ---- Intruder staging (manual) ------------------------------------------

    private static ToolResult stageInIntruder(Map<String, Object> args, ToolContext ctx) {
        HttpRequest request = Tools.resolveRequest(args, ctx);
        if (request == null) {
            return ToolResult.error("Provide request_id or url.");
        }
        try {
            ctx.api.intruder().sendToIntruder(request);
        } catch (RuntimeException e) {
            return ToolResult.error("Could not stage in Intruder: " + e.getMessage());
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("staged", true);
        try {
            data.put("url", request.url());
        } catch (RuntimeException ignored) {
        }
        data.put("note", "Request staged in Intruder. Configure payload positions and start the attack in the UI; "
                + "the Montoya API cannot auto-run it. For automated fuzzing use fuzz_request instead.");
        return ToolResult.ok(data);
    }
}
