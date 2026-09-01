/*
 * Optional Burp passive scan check: when enabled in Settings, in-scope HTTP
 * exchanges are sent to the local model and any JSON findings become native
 * Burp issues. When disabled (the default) doCheck returns immediately and
 * nothing is sent to the model.
 */
package com.cybernexis.agent.scanner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import com.cybernexis.agent.Config;
import com.cybernexis.agent.Branding;
import com.cybernexis.agent.json.Json;
import com.cybernexis.agent.ollama.OllamaClient;
import com.cybernexis.agent.tools.Tools;

public final class AiPassiveScanCheck implements PassiveScanCheck {

    private static final int REQ_CHARS = 3500;
    private static final int RESP_CHARS = 3500;
    private static final int MAX_FINDINGS = 3;
    private static final int SEEN_CAP = 400;
    private static final int LLM_TIMEOUT_SECONDS = 40;
    private static final String ISSUE_PREFIX = Branding.SHORT + ": ";
    private static final String BACKGROUND =
            "Identified by the " + Branding.PRODUCT + " passive scanner. Treat as a lead and verify "
                    + "manually before reporting — LLM output can be incomplete or overly confident.";

    private static final String SYSTEM =
            "You are a passive HTTP security reviewer. Analyse ONLY the given request/response. "
                    + "Report issues that are evidenced in this exchange: info disclosure, tokens in URLs, "
                    + "verbose errors, CORS reflecting untrusted origins, missing auth on sensitive JSON, "
                    + "secrets in bodies, insecure cookies. Do not invent vulns. Do not suggest active tests. "
                    + "Reply with a single JSON object and nothing else: "
                    + "{\"findings\":[{\"name\":\"short title\",\"severity\":\"HIGH|MEDIUM|LOW|INFORMATION\","
                    + "\"detail\":\"what is evidenced\",\"remediation\":\"how to fix\"}]}. "
                    + "If nothing solid, return {\"findings\":[]}.";

    private final Config config;
    private final OllamaClient client;
    private final MontoyaApi api;
    private final Semaphore slot = new Semaphore(1);
    private final Set<String> seen = Collections.synchronizedSet(new LinkedHashSet<>());
    private volatile boolean wasEnabled;

    public AiPassiveScanCheck(Config config, OllamaClient client, MontoyaApi api) {
        this.config = config;
        this.client = client;
        this.api = api;
    }

    @Override
    public String checkName() {
        return Branding.PRODUCT + " passive";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse base) {
        if (config == null || !config.passiveAiScan) {
            wasEnabled = false;
            return AuditResult.auditResult();
        }
        if (!wasEnabled) {
            seen.clear();
            wasEnabled = true;
        }
        if (base == null || !base.hasResponse() || base.response() == null) {
            return AuditResult.auditResult();
        }

        HttpRequest req;
        HttpResponse resp;
        String url;
        try {
            req = base.request();
            resp = base.response();
            url = req.url();
        } catch (RuntimeException e) {
            return AuditResult.auditResult();
        }

        if (skipScope(url) || skipStatic(req, resp) || alreadySeen(req)) {
            return AuditResult.auditResult();
        }

        if (!slot.tryAcquire()) {
            // Another analysis is in flight — skip rather than stall Burp's scanner thread.
            forget(req);
            return AuditResult.auditResult();
        }
        OllamaClient.CancelToken cancel = new OllamaClient.CancelToken();
        Thread watchdog = startWatchdog(cancel, LLM_TIMEOUT_SECONDS);
        try {
            List<Map<String, Object>> messages = new ArrayList<>();
            messages.add(message("system", SYSTEM));
            messages.add(message("user", dump(req, resp)));
            OllamaClient.ChatResult result = client.streamChat(messages, null, null, cancel);
            if (result == null || result.content == null || result.content.isBlank()) {
                return AuditResult.auditResult();
            }
            List<AuditIssue> issues = parseFindings(result.content, url, base);
            if (!issues.isEmpty()) {
                try {
                    api.logging().logToOutput(Branding.PRODUCT + " passive: " + issues.size()
                            + " finding(s) on " + req.method() + " " + url);
                } catch (RuntimeException ignored) {
                }
            }
            return issues.isEmpty()
                    ? AuditResult.auditResult()
                    : AuditResult.auditResult(issues);
        } catch (Exception e) {
            try {
                api.logging().logToError(Branding.PRODUCT + " passive: " + e.getMessage());
            } catch (RuntimeException ignored) {
            }
            forget(req);
            return AuditResult.auditResult();
        } finally {
            watchdog.interrupt();
            slot.release();
        }
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (existingIssue == null || newIssue == null) {
            return ConsolidationAction.KEEP_BOTH;
        }
        String a = existingIssue.name();
        String b = newIssue.name();
        if (a != null && a.equals(b)) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    private boolean skipScope(String url) {
        try {
            return !api.scope().isInScope(url);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean skipStatic(HttpRequest req, HttpResponse resp) {
        try {
            String path = req.pathWithoutQuery();
            if (path != null) {
                String lower = path.toLowerCase();
                if (lower.matches(".*\\.(png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|mp4|mp3|avi|css|map)$")) {
                    return true;
                }
            }
        } catch (RuntimeException ignored) {
        }
        try {
            MimeType mime = resp.statedMimeType();
            if (mime == null) {
                mime = resp.mimeType();
            }
            if (mime != null) {
                switch (mime) {
                    case CSS:
                    case IMAGE_UNKNOWN:
                    case IMAGE_JPEG:
                    case IMAGE_GIF:
                    case IMAGE_PNG:
                    case IMAGE_BMP:
                    case IMAGE_TIFF:
                    case IMAGE_SVG_XML:
                    case SOUND:
                    case VIDEO:
                    case FONT_WOFF:
                    case FONT_WOFF2:
                    case APPLICATION_FLASH:
                        return true;
                    default:
                        break;
                }
            }
        } catch (RuntimeException ignored) {
        }
        try {
            short status = resp.statusCode();
            if (status == 204 || status == 304) {
                return true;
            }
        } catch (RuntimeException ignored) {
        }
        return false;
    }

    private boolean alreadySeen(HttpRequest req) {
        String key = keyOf(req);
        synchronized (seen) {
            if (!seen.add(key)) {
                return true;
            }
            while (seen.size() > SEEN_CAP) {
                String first = seen.iterator().next();
                seen.remove(first);
            }
        }
        return false;
    }

    private void forget(HttpRequest req) {
        synchronized (seen) {
            seen.remove(keyOf(req));
        }
    }

    private static String keyOf(HttpRequest req) {
        try {
            return req.method() + " " + req.httpService().host() + req.pathWithoutQuery();
        } catch (RuntimeException e) {
            return String.valueOf(System.identityHashCode(req));
        }
    }

    private static String dump(HttpRequest req, HttpResponse resp) {
        StringBuilder sb = new StringBuilder();
        try {
            sb.append("REQUEST\n").append(Tools.truncate(req.toString(), REQ_CHARS));
        } catch (RuntimeException e) {
            sb.append("REQUEST\n<unreadable>");
        }
        sb.append("\n\nRESPONSE\n");
        try {
            sb.append(Tools.truncate(resp.toString(), RESP_CHARS));
        } catch (RuntimeException e) {
            sb.append("<unreadable>");
        }
        return sb.toString();
    }

    private static List<AuditIssue> parseFindings(String content, String url, HttpRequestResponse evidence) {
        Map<String, Object> obj = Json.parseObject(extractJsonObject(content));
        List<AuditIssue> out = new ArrayList<>();
        for (Object item : Json.asList(obj.get("findings"))) {
            if (out.size() >= MAX_FINDINGS) {
                break;
            }
            Map<String, Object> f = Json.asMap(item);
            String name = Json.asString(f.get("name"), "").trim();
            if (name.isEmpty()) {
                continue;
            }
            if (!name.startsWith(ISSUE_PREFIX)) {
                name = ISSUE_PREFIX + name;
            }
            AuditIssueSeverity severity = parseSeverity(Json.asString(f.get("severity"), "INFORMATION"));
            String detail = htmlSafe(Json.asString(f.get("detail"), ""));
            String remediation = htmlSafe(Json.asString(f.get("remediation"), ""));
            try {
                out.add(AuditIssue.auditIssue(
                        name, detail, remediation, url, severity, AuditIssueConfidence.TENTATIVE,
                        BACKGROUND, null, severity, evidence));
            } catch (RuntimeException ignored) {
            }
        }
        return out;
    }

    private static String extractJsonObject(String content) {
        if (content == null) {
            return "{}";
        }
        String s = content.trim();
        if (s.startsWith("```")) {
            int nl = s.indexOf('\n');
            if (nl > 0) {
                s = s.substring(nl + 1);
            }
            int fence = s.lastIndexOf("```");
            if (fence >= 0) {
                s = s.substring(0, fence);
            }
            s = s.trim();
        }
        int start = s.indexOf('{');
        int end = s.lastIndexOf('}');
        if (start >= 0 && end > start) {
            return s.substring(start, end + 1);
        }
        return s;
    }

    private static AuditIssueSeverity parseSeverity(String s) {
        if (s == null) {
            return AuditIssueSeverity.INFORMATION;
        }
        switch (s.trim().toUpperCase()) {
            case "HIGH":
            case "CRITICAL":
                return AuditIssueSeverity.HIGH;
            case "MEDIUM":
                return AuditIssueSeverity.MEDIUM;
            case "LOW":
                return AuditIssueSeverity.LOW;
            default:
                return AuditIssueSeverity.INFORMATION;
        }
    }

    private static String htmlSafe(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static Map<String, Object> message(String role, String content) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("role", role);
        m.put("content", content);
        return m;
    }

    private static Thread startWatchdog(OllamaClient.CancelToken cancel, int seconds) {
        Thread t = new Thread(() -> {
            try {
                TimeUnit.SECONDS.sleep(seconds);
                cancel.cancel();
            } catch (InterruptedException ignored) {
            }
        }, "cybernexis-passive-watchdog");
        t.setDaemon(true);
        t.start();
        return t;
    }
}
