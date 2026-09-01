/*
 * Heuristic scan of a raw HTTP request/response for tokens worth remembering:
 * JWTs, UUIDs, API keys, CSRF fields, session cookies, Bearer headers.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class TokenScanner {

    public static final class Hit {
        public final String kind;
        public final String name;
        public final String where;
        public final String value;
        /** Durable fact to set if the host has no value for this key yet. */
        public final String factKey;
        public final String factValue;

        Hit(String kind, String name, String where, String value) {
            this(kind, name, where, value, null, null);
        }

        Hit(String kind, String name, String where, String value, String factKey, String factValue) {
            this.kind = kind;
            this.name = name;
            this.where = where;
            this.value = value;
            this.factKey = factKey;
            this.factValue = factValue;
        }
    }

    private static final int BODY_SCAN = 24_000;
    private static final int MAX_HITS = 16;

    private static final Pattern JWT = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}");
    private static final Pattern UUID = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");
    private static final Pattern SET_COOKIE = Pattern.compile(
            "(?im)^set-cookie:\\s*([^=\\s;]+)=([^;\\r\\n]*)");
    private static final Pattern AUTH = Pattern.compile(
            "(?im)^authorization:\\s*(Bearer|Basic|JWT)\\s+(\\S+)");
    private static final Pattern API_HEADER = Pattern.compile(
            "(?im)^(x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token):\\s*(\\S+)");
    private static final Pattern JSON_SECRET = Pattern.compile(
            "(?i)\"(access_token|refresh_token|id_token|csrf[_-]?token|anti[_-]?forgery|api[_-]?key|token)\"\\s*:\\s*\"([^\"]{8,})\"");
    private static final Pattern FORM_CSRF = Pattern.compile(
            "(?is)name=[\"'](__RequestVerificationToken|_csrf|csrf[_-]?token|_token|antiforgery)[\"'][^>]*value=[\"']([^\"']+)[\"']"
                    + "|value=[\"']([^\"']+)[\"'][^>]*name=[\"'](__RequestVerificationToken|_csrf|csrf[_-]?token|_token)[\"']");
    private static final Pattern META_CSRF = Pattern.compile(
            "(?i)(?:name|property)=[\"']csrf-token[\"'][^>]*content=[\"']([^\"']+)[\"']");
    private static final Pattern REQ_LINE = Pattern.compile(
            "(?i)^(GET|POST|PUT|PATCH|DELETE)\\s+(\\S+)");
    private static final Pattern LOGIN_PATH = Pattern.compile(
            "(?i)/(?:(?:api|account|user)s?/)?(?:login|signin|sign-in|auth|session|oturum)(?:/|\\?|$)");

    private static final Set<String> SESSION_COOKIES = Set.of(
            "jsessionid", "phpsessid", "asp.net_sessionid", ".aspxauth", "sid",
            "session", "sessionid", "auth", "token", "jwt", "access_token",
            "refresh_token", "id_token", "authorization", "csrf", "xsrf-token",
            "xsrf_token", "requestverificationtoken");

    private TokenScanner() {
    }

    public static List<Hit> scan(String request, String response) {
        List<Hit> hits = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        scanMessage(hits, seen, request, "request");
        scanMessage(hits, seen, response, "response");
        if (hits.size() > MAX_HITS) {
            return new ArrayList<>(hits.subList(0, MAX_HITS));
        }
        return hits;
    }

    private static void scanMessage(List<Hit> hits, Set<String> seen, String raw, String side) {
        if (raw == null || raw.isEmpty()) {
            return;
        }
        String headers;
        String body;
        int split = indexOfBody(raw);
        if (split >= 0) {
            headers = raw.substring(0, split);
            body = raw.substring(split);
            if (body.length() > BODY_SCAN) {
                body = body.substring(0, BODY_SCAN);
            }
        } else {
            headers = raw.length() > BODY_SCAN ? raw.substring(0, BODY_SCAN) : raw;
            body = "";
        }

        if ("request".equals(side)) {
            Matcher line = REQ_LINE.matcher(headers);
            if (line.find() && LOGIN_PATH.matcher(line.group(2)).find()) {
                add(hits, seen, new Hit("path", "login_path", "request line", line.group(2),
                        "login_path", pathOnly(line.group(2))));
                add(hits, seen, new Hit("path", "login_method", "request line", line.group(1),
                        "login_method", line.group(1).toUpperCase(Locale.ROOT)));
            }
        }

        Matcher auth = AUTH.matcher(headers);
        while (auth.find() && hits.size() < MAX_HITS) {
            String scheme = auth.group(1);
            String val = auth.group(2);
            String kind = looksLikeJwt(val) ? "jwt" : "bearer";
            add(hits, seen, new Hit(kind, "Authorization", side + " header Authorization", val,
                    "auth_scheme", scheme));
        }

        Matcher api = API_HEADER.matcher(headers);
        while (api.find() && hits.size() < MAX_HITS) {
            String header = api.group(1);
            String kind = header.toLowerCase(Locale.ROOT).contains("csrf")
                    || header.toLowerCase(Locale.ROOT).contains("xsrf") ? "csrf" : "api_key";
            String fact = "csrf".equals(kind) ? "csrf_header" : "api_header";
            add(hits, seen, new Hit(kind, header, side + " header " + header, api.group(2),
                    fact, header));
        }

        Matcher cookie = SET_COOKIE.matcher(headers);
        while (cookie.find() && hits.size() < MAX_HITS) {
            String name = cookie.group(1);
            String val = cookie.group(2);
            boolean session = isSessionCookie(name) || looksLikeJwt(val);
            if (!session) {
                continue;
            }
            String kind = looksLikeJwt(val) ? "jwt" : "cookie";
            add(hits, seen, new Hit(kind, name, "Set-Cookie", val,
                    isSessionCookie(name) ? "session_cookie" : null,
                    isSessionCookie(name) ? name : null));
        }

        Matcher jwt = JWT.matcher(headers + "\n" + body);
        while (jwt.find() && hits.size() < MAX_HITS) {
            add(hits, seen, new Hit("jwt", "jwt", side + " body/header", jwt.group()));
        }

        Matcher json = JSON_SECRET.matcher(body);
        while (json.find() && hits.size() < MAX_HITS) {
            String key = json.group(1);
            String val = json.group(2);
            String kind = key.toLowerCase(Locale.ROOT).contains("csrf") ? "csrf"
                    : looksLikeJwt(val) ? "jwt" : "api_key";
            String fact = "csrf".equals(kind) ? "csrf_field" : null;
            add(hits, seen, new Hit(kind, key, "JSON " + key, val, fact, "csrf".equals(kind) ? key : null));
        }

        Matcher form = FORM_CSRF.matcher(body);
        while (form.find() && hits.size() < MAX_HITS) {
            String field = form.group(1) != null ? form.group(1) : form.group(4);
            String val = form.group(2) != null ? form.group(2) : form.group(3);
            if (field != null && val != null) {
                add(hits, seen, new Hit("csrf", field, "form field " + field, val, "csrf_field", field));
            }
        }

        Matcher meta = META_CSRF.matcher(body);
        if (meta.find()) {
            add(hits, seen, new Hit("csrf", "csrf-token", "meta csrf-token", meta.group(1),
                    "csrf_field", "csrf-token"));
        }

        // Path UUIDs only — body UUIDs in minified JS are noise.
        if ("request".equals(side)) {
            Matcher line = REQ_LINE.matcher(headers);
            if (line.find()) {
                Matcher uuid = UUID.matcher(line.group(2));
                int n = 0;
                while (uuid.find() && n++ < 3 && hits.size() < MAX_HITS) {
                    add(hits, seen, new Hit("uuid", "id", "path", uuid.group()));
                }
            }
        }
    }

    private static void add(List<Hit> hits, Set<String> seen, Hit hit) {
        if (hit.value == null || hit.value.isEmpty()) {
            return;
        }
        String sig = hit.kind + "|" + hit.name.toLowerCase(Locale.ROOT) + "|" + hit.value;
        if (!seen.add(sig)) {
            return;
        }
        hits.add(hit);
    }

    private static boolean looksLikeJwt(String value) {
        return value != null && value.startsWith("eyJ") && value.indexOf('.') > 0;
    }

    private static boolean isSessionCookie(String name) {
        if (name == null) {
            return false;
        }
        String n = name.toLowerCase(Locale.ROOT);
        if (SESSION_COOKIES.contains(n)) {
            return true;
        }
        return n.contains("session") || n.contains("auth") || n.endsWith("token")
                || n.contains("jwt");
    }

    private static int indexOfBody(String raw) {
        int crlf = raw.indexOf("\r\n\r\n");
        int lf = raw.indexOf("\n\n");
        if (crlf < 0) {
            return lf;
        }
        if (lf < 0) {
            return crlf;
        }
        return Math.min(crlf, lf);
    }

    private static String pathOnly(String uri) {
        int q = uri.indexOf('?');
        return q >= 0 ? uri.substring(0, q) : uri;
    }
}
