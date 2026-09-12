/*
 * Lightweight classification of Burp state (sitemap, issues, HTTP, token map)
 * into vuln-class scores that map onto Playbooks names. No payloads — evidence
 * strings only, so the agent can pick IDOR vs JWT vs GraphQL from live context.
 */
package com.cybernexis.agent.tools;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

public final class SurfaceHints {

    public static final int AUTO_ATTACH_MIN = 25;

    public static final class Hit {
        public final String playbook;
        public final int score;
        public final List<String> evidence;

        Hit(String playbook, int score, List<String> evidence) {
            this.playbook = playbook;
            this.score = score;
            this.evidence = evidence;
        }
    }

    public static final class Report {
        public final List<Hit> ranked;

        Report(List<Hit> ranked) {
            this.ranked = ranked;
        }

        public boolean isEmpty() {
            return ranked.isEmpty();
        }

        public Hit top() {
            return ranked.isEmpty() ? null : ranked.get(0);
        }

        /** True when the leading class is strong enough to auto-load a playbook. */
        public boolean strongEnough() {
            Hit t = top();
            return t != null && t.score >= AUTO_ATTACH_MIN;
        }

        public String promptBlock() {
            if (ranked.isEmpty()) {
                return "- Surface hints: none yet (browse the host or send a request).\n";
            }
            StringBuilder sb = new StringBuilder();
            sb.append("- Surface hints (sitemap / issues / HTTP / tokens), strongest first:\n");
            int n = 0;
            for (Hit h : ranked) {
                if (n++ >= 5) {
                    break;
                }
                sb.append("    ").append(h.playbook).append(" (").append(h.score).append("): ")
                  .append(String.join("; ", h.evidence)).append('\n');
            }
            Hit t = top();
            if (t != null && t.score >= AUTO_ATTACH_MIN) {
                sb.append("  If the user asked to test or analyze (or sent a request), start the ")
                  .append(t.playbook).append(" playbook: read-only first, then confirm.\n");
            }
            return sb.toString();
        }
    }

    private static final Pattern OBJECT_PATH = Pattern.compile(
            "/(?:users?|accounts?|orders?|items?|docs?|documents?|files?|profiles?|customers?|invoices?)/"
                    + "(?:\\d+|[0-9a-fA-F-]{8,})",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern GRAPHQL_BODY = Pattern.compile(
            "(?i)(?:\"query\"\\s*:|\\bquery\\s*\\(|\\bmutation\\s*\\(|\\b__schema\\b|application/graphql)");

    private SurfaceHints() {
    }

    /** Scan live Burp state for the focus host (or the whole project if focus is null). */
    public static Report scan(ToolContext ctx, HttpRequestResponse extra) {
        return scan(ctx, ctx == null ? null : ctx.focusHost(), extra);
    }

    public static Report scan(ToolContext ctx, String focusHost, HttpRequestResponse extra) {
        Acc acc = new Acc();
        String focus = Focus.normalize(focusHost);

        if (ctx != null && ctx.api != null) {
            try {
                int n = 0;
                for (HttpRequestResponse hrr : ctx.api.siteMap().requestResponses()) {
                    if (n++ > 250) {
                        break;
                    }
                    considerExchange(acc, focus, hrr, "sitemap");
                }
            } catch (RuntimeException ignored) {
            }
            try {
                int n = 0;
                for (AuditIssue issue : ctx.api.siteMap().issues()) {
                    if (n++ > 80) {
                        break;
                    }
                    considerIssue(acc, focus, issue);
                }
            } catch (RuntimeException ignored) {
            }
        }

        if (ctx != null && ctx.memory != null && focus != null) {
            for (TargetMemory.Token t : ctx.memory.tokens(focus)) {
                considerTokenKind(acc, t.kind, "token map " + t.name);
            }
        }

        if (ctx != null && ctx.messages != null) {
            int n = 0;
            for (MessageStore.Entry e : ctx.messages.all()) {
                if (n++ > 40) {
                    break;
                }
                considerExchange(acc, focus, e.message, e.source);
            }
        }

        if (extra != null) {
            considerExchange(acc, focus, extra, "this request");
        }

        return acc.report();
    }

    /** Testable: score a single URL. */
    public static void considerUrl(Acc acc, String method, String url, String source) {
        if (acc == null || url == null || url.isEmpty()) {
            return;
        }
        String u = url.toLowerCase(Locale.ROOT);
        String src = source == null ? "url" : source;
        String path;
        String query;
        try {
            URI parsed = URI.create(url);
            path = parsed.getPath() == null ? "" : parsed.getPath().toLowerCase(Locale.ROOT);
            query = parsed.getRawQuery() == null ? "" : parsed.getRawQuery().toLowerCase(Locale.ROOT);
        } catch (RuntimeException e) {
            path = u;
            query = u;
        }

        if (path.contains("graphql") || path.contains("/gql") || u.contains("application/graphql")) {
            acc.add("GraphQL", 40, src + " " + shorten(url));
        }
        if (path.contains("oauth") || path.contains("openid") || path.contains("/authorize")
                || path.contains("/callback") && (query.contains("client_id") || query.contains("code="))) {
            acc.add("OAuth / OIDC", 35, src + " " + shorten(url));
        }
        if (path.contains("/api/") || path.contains("/v1/") || path.contains("/v2/")
                || path.contains("swagger") || path.contains("openapi")) {
            acc.add("API security", 12, src + " API path " + shorten(url));
        }
        if (OBJECT_PATH.matcher(path).find() || queryContains(query, "id", "user_id", "userid", "account_id", "order_id")) {
            acc.add("IDOR / BOLA", 26, src + " object id " + shorten(url));
        }
        if (queryContains(query, "url", "uri", "dest", "destination", "webhook", "fetch",
                "proxy", "target", "feed", "image", "file", "callback")
                || path.contains("webhook") || path.contains("/proxy") || path.contains("/fetch")) {
            acc.add("SSRF", 28, src + " fetch-like param " + shorten(url));
        }
        if (queryContains(query, "redirect", "redirect_uri", "returnurl", "return_url", "next", "goto", "continue")) {
            acc.add("Open redirect / HPP", 22, src + " redirect param " + shorten(url));
        }
        if (path.contains("cart") || path.contains("checkout") || path.contains("coupon")
                || path.contains("discount") || path.contains("refund") || path.contains("/pay")) {
            acc.add("Business logic", 22, src + " " + shorten(url));
        }
        if (queryContains(query, "q", "query", "search", "s", "filter", "sort")) {
            acc.add("XSS", 8, src + " reflected input " + shorten(url));
            acc.add("SQLi", 8, src + " filter/search " + shorten(url));
        }
        if (method != null && "POST".equalsIgnoreCase(method) && path.contains("login")) {
            acc.add("JWT", 6, src + " login POST");
        }
    }

    public static void considerIssueName(Acc acc, String name, String url) {
        if (acc == null || name == null || name.isBlank()) {
            return;
        }
        String n = name.toLowerCase(Locale.ROOT);
        String ev = "issue \"" + name + "\"" + (url == null ? "" : " @ " + shorten(url));
        if (containsAny(n, "sql injection", "sqli", "sql synta", "blind sql")) {
            acc.add("SQLi", 50, ev);
        }
        if (containsAny(n, "cross-site scripting", "cross site scripting", "xss")) {
            acc.add("XSS", 50, ev);
        }
        if (containsAny(n, "ssrf", "server-side request", "external service interaction", "out-of-band resource")) {
            acc.add("SSRF", 50, ev);
        }
        if (containsAny(n, "open redirection", "open redirect")) {
            acc.add("Open redirect / HPP", 50, ev);
        }
        if (containsAny(n, "graphql")) {
            acc.add("GraphQL", 50, ev);
        }
        if (containsAny(n, "oauth", "openid")) {
            acc.add("OAuth / OIDC", 50, ev);
        }
        if (containsAny(n, "jwt", "json web token")) {
            acc.add("JWT", 50, ev);
        }
        if (containsAny(n, "idor", "insecure direct object", "broken object", "bola")) {
            acc.add("IDOR / BOLA", 50, ev);
        }
        if (containsAny(n, "access control", "privilege", "authorization")) {
            acc.add("IDOR / BOLA", 18, ev);
        }
    }

    public static void considerHttp(Acc acc, String request, String response, String source) {
        if (acc == null) {
            return;
        }
        String src = source == null ? "http" : source;
        String req = request == null ? "" : request;
        String res = response == null ? "" : response;
        String both = (req + "\n" + res);
        if (both.length() > 16_000) {
            both = both.substring(0, 16_000);
        }

        if (GRAPHQL_BODY.matcher(both).find()) {
            acc.add("GraphQL", 36, src + " GraphQL body/content-type");
        }
        for (TokenScanner.Hit hit : TokenScanner.scan(req, res)) {
            considerTokenKind(acc, hit.kind, src + " " + hit.where);
        }
        String lower = both.toLowerCase(Locale.ROOT);
        if (lower.contains("application/json") && (lower.contains("\"id\"") || lower.contains("/users/"))) {
            acc.add("IDOR / BOLA", 10, src + " JSON object id");
            acc.add("API security", 10, src + " JSON API");
        }
    }

    public static void considerTokenKind(Acc acc, String kind, String where) {
        if (acc == null || kind == null) {
            return;
        }
        String k = kind.toLowerCase(Locale.ROOT);
        if ("jwt".equals(k)) {
            acc.add("JWT", 34, where == null ? "JWT" : where);
        } else if ("bearer".equals(k) || "api_key".equals(k) || "api-key".equals(k)) {
            acc.add("API security", 12, where == null ? k : where);
            acc.add("JWT", 8, where == null ? k : where);
        }
    }

    public static final class Acc {
        private final Map<String, Integer> scores = new LinkedHashMap<>();
        private final Map<String, List<String>> evidence = new LinkedHashMap<>();

        public void add(String playbook, int score, String ev) {
            if (playbook == null || score <= 0) {
                return;
            }
            scores.merge(playbook, score, Integer::sum);
            List<String> list = evidence.computeIfAbsent(playbook, k -> new ArrayList<>());
            if (ev != null && !ev.isEmpty() && list.size() < 3 && !list.contains(ev)) {
                list.add(ev);
            }
        }

        public Report report() {
            List<Hit> hits = new ArrayList<>();
            for (Map.Entry<String, Integer> e : scores.entrySet()) {
                hits.add(new Hit(e.getKey(), e.getValue(),
                        evidence.getOrDefault(e.getKey(), List.of())));
            }
            hits.sort((a, b) -> Integer.compare(b.score, a.score));
            return new Report(hits);
        }
    }

    private static void considerExchange(Acc acc, String focus, HttpRequestResponse hrr, String source) {
        if (hrr == null) {
            return;
        }
        try {
            String url = hrr.request().url();
            if (focus != null && !Focus.urlMatches(url, focus)) {
                return;
            }
            considerUrl(acc, hrr.request().method(), url, source);
            String req = hrr.request().toString();
            String res = hrr.hasResponse() ? hrr.response().toString() : "";
            considerHttp(acc, req, res, source);
        } catch (RuntimeException ignored) {
        }
    }

    private static void considerIssue(Acc acc, String focus, AuditIssue issue) {
        if (issue == null) {
            return;
        }
        try {
            String url = issue.baseUrl();
            if (focus != null && url != null && !Focus.urlMatches(url, focus)) {
                return;
            }
            considerIssueName(acc, issue.name(), url);
        } catch (RuntimeException ignored) {
        }
    }

    private static boolean queryContains(String query, String... keys) {
        if (query == null || query.isEmpty()) {
            return false;
        }
        for (String key : keys) {
            if (query.contains(key + "=") || query.startsWith(key + "=") || query.contains("&" + key + "=")) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsAny(String hay, String... needles) {
        for (String n : needles) {
            if (hay.contains(n)) {
                return true;
            }
        }
        return false;
    }

    private static String shorten(String url) {
        if (url == null) {
            return "";
        }
        return url.length() <= 96 ? url : url.substring(0, 93) + "...";
    }
}
