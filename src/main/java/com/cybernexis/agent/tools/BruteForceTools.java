/*
 * Credential stuffing / password spraying. The model picks a built-in wordlist
 * (or a small custom payloads[] / usernames[]) instead of emitting hundreds of
 * passwords in a tool call — that is what stalled login brute-force runs.
 *
 * Results are clustered by (status, length); only likely hits and lockout
 * samples are stored in the message index so the LLM context stays small.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public final class BruteForceTools {

    private static final int HARD_MAX = 2000;
    private static final int DEFAULT_MAX = 250;
    private static final int DEFAULT_CONCURRENCY = 4;
    private static final int MAX_CONCURRENCY = 10;
    private static final int HIT_LENGTH_DELTA = 80;
    private static final int CLUSTER_SAMPLES = 3;
    private static final int MAX_HITS_IN_RESULT = 20;
    private static final int PAYLOAD_ECHO_MAX = 80;

    private static final String[] PASS_MARKERS = {"{{pass}}", "{{password}}", "FUZZ"};
    private static final String[] USER_MARKERS = {"{{user}}", "{{username}}"};

    private static final String[] FAIL_SIGNATURES = {
            "invalid", "incorrect", "wrong password", "authentication failed",
            "unauthorized", "unauthorised", "bad credentials", "login failed",
            "user not found", "account not found",
            "hatalı", "hatali", "yanlış", "yanlis", "geçersiz", "gecersiz",
            "kullanıcı adı veya", "kullanici adi veya"
    };

    private static final String[] HIT_SIGNATURES = {
            "access_token", "refresh_token", "id_token", "\"token\"",
            "bearer ", "\"jwt\"", "\"success\":true", "\"success\": true",
            "\"authenticated\":true", "\"isauthenticated\":true",
            "giriş başarılı", "giris basarili", "login successful"
    };

    private static final String[] LOCKOUT_SIGNATURES = {
            "locked", "lockout", "too many", "rate limit", "rate-limit",
            "temporarily blocked", "try again later", "account disabled",
            "hesap kilit", "çok fazla", "cok fazla", "geçici olarak",
            "captcha", "recaptcha"
    };

    private BruteForceTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "list_wordlists",
                "List built-in wordlists for brute_force (name, size). Use these instead of pasting passwords.",
                false,
                ToolDescriptor.emptyParams(),
                (a, c) -> ToolResult.ok(mapOf("wordlists", Wordlists.catalog()))));

        registry.register(new ToolDescriptor(
                "brute_force",
                "Password spray / credential stuffing against a login (or any one/two-field form). "
                        + "Do NOT paste a password list — pick wordlist=passwords-top250 (or top100/top500). "
                        + "Put {{pass}} in the password field of the request body (and optional {{user}}). "
                        + "Example: url + method=POST + edits=[{header:Content-Type,value:application/json},"
                        + "{body:{\"username\":\"admin\",\"password\":\"{{pass}}\"}}] + wordlist=passwords-top250. "
                        + "Sends live traffic, clusters responses, stops early on a likely hit or lockout. "
                        + "args: request_id|url|host, method?, edits[]?, wordlist?, payloads[]?, username?, usernames[]?, "
                        + "username_wordlist?, location?, parameter?, marker?, user_marker?, stop_on_hit?, "
                        + "concurrency?, delay_ms?, max_attempts?.",
                true,
                Schema.object()
                        .prop("request_id", "integer", "Stored message id to use as the base request.")
                        .prop("url", "string", "URL for a new base request (typical: the login endpoint).")
                        .prop("host", "string", "Host for a new base request.")
                        .prop("method", "string", "Override HTTP method (login is usually POST).")
                        .arrayProp("edits", "object", "Base-request edits. Put {{pass}} in the password field.")
                        .prop("wordlist", "string", "passwords-top100 | passwords-top250 (default) | passwords-top500.")
                        .arrayProp("payloads", "string", "Optional extra passwords (keep small; prefer wordlist).")
                        .prop("username", "string", "Single username to spray (replaces {{user}} if present).")
                        .arrayProp("usernames", "string", "Optional username list for credential stuffing.")
                        .prop("username_wordlist", "string", "usernames-common — spray those names with each password.")
                        .prop("location", "string", "json_body | body | query | header | cookie | path (when no {{pass}} marker).")
                        .prop("parameter", "string", "Password field name when not using a marker (default password).")
                        .prop("marker", "string", "Password placeholder; default auto-detects {{pass}} / {{password}} / FUZZ.")
                        .prop("user_marker", "string", "Username placeholder; default auto-detects {{user}} / {{username}}.")
                        .prop("stop_on_hit", "boolean", "Stop after the first likely success (default true).")
                        .prop("concurrency", "integer", "Parallel requests 1-10 (default 4). Use 1 to observe lockout timing.")
                        .prop("delay_ms", "integer", "Delay between submissions in ms (honoured when concurrency=1).")
                        .prop("max_attempts", "integer", "Cap on attempts (default 250, hard max 2000).")
                        .build(),
                BruteForceTools::bruteForce));
    }

    private static ToolResult bruteForce(Map<String, Object> args, ToolContext ctx) {
        HttpRequest base = Tools.resolveRequest(args, ctx);
        if (base == null) {
            return ToolResult.error("Provide request_id, url, or host. For a JSON login, also set method=POST and "
                    + "edits so the body contains {\"username\":\"admin\",\"password\":\"{{pass}}\"}.");
        }

        String raw;
        try {
            raw = base.toString();
        } catch (RuntimeException e) {
            raw = "";
        }

        String passMarker = firstPresent(raw, Tools.str(args, "marker"), PASS_MARKERS);
        String userMarker = firstPresent(raw, Tools.str(args, "user_marker"), USER_MARKERS);
        String location = Tools.str(args, "location", passMarker != null ? "marker" : "json_body").toLowerCase();
        String parameter = Tools.str(args, "parameter", "password");

        if (passMarker == null && "marker".equals(location)) {
            return ToolResult.error("No password marker found. Put {{pass}} in the request body via edits, "
                    + "or set location=json_body and parameter=password.");
        }

        List<String> passwords = new ArrayList<>();
        passwords.addAll(Tools.strList(args, "payloads"));
        String wordlistName = Tools.str(args, "wordlist");
        if (wordlistName == null && passwords.isEmpty()) {
            wordlistName = Wordlists.PASSWORDS_TOP250;
        }
        if (wordlistName != null) {
            try {
                passwords.addAll(Wordlists.load(wordlistName));
            } catch (IllegalArgumentException e) {
                return ToolResult.error(e.getMessage());
            }
        }
        if (passwords.isEmpty()) {
            return ToolResult.error("No passwords. Pass wordlist=passwords-top250 or a small payloads[] list.");
        }

        List<String> usernames = new ArrayList<>();
        String singleUser = Tools.interp(ctx, Tools.str(args, "username"));
        usernames.addAll(Tools.strList(args, "usernames"));
        String userListName = Tools.str(args, "username_wordlist");
        if (userListName != null) {
            try {
                usernames.addAll(Wordlists.load(userListName));
            } catch (IllegalArgumentException e) {
                return ToolResult.error(e.getMessage());
            }
        }
        if (usernames.isEmpty() && singleUser != null) {
            usernames.add(singleUser);
        }
        if (usernames.isEmpty()) {
            usernames.add(null); // password-only spray; leave username as in the base request
        }

        int max = Math.min(Math.max(1, Tools.intOr(args, "max_attempts", DEFAULT_MAX)), HARD_MAX);
        boolean stopOnHit = Tools.boolOr(args, "stop_on_hit", true);
        int concurrency = Math.min(Math.max(1, Tools.intOr(args, "concurrency", DEFAULT_CONCURRENCY)), MAX_CONCURRENCY);
        int delay = Math.max(0, Tools.intOr(args, "delay_ms", 0));

        List<Attempt> plan = new ArrayList<>();
        outer:
        for (String user : usernames) {
            for (String pass : passwords) {
                plan.add(new Attempt(user, pass));
                if (plan.size() >= max) {
                    break outer;
                }
            }
        }

        Probe baseline = send(ctx, base);
        ConcurrentLinkedQueue<Row> rows = new ConcurrentLinkedQueue<>();
        AtomicInteger sent = new AtomicInteger();
        AtomicBoolean stop = new AtomicBoolean(false);
        AtomicInteger lockoutCount = new AtomicInteger();

        ExecutorService pool = Executors.newFixedThreadPool(concurrency);
        Semaphore slots = new Semaphore(concurrency);
        try {
            for (Attempt attempt : plan) {
                if (stop.get()) {
                    break;
                }
                if (concurrency == 1 && delay > 0 && sent.get() > 0) {
                    sleep(delay);
                }
                slots.acquireUninterruptibly();
                if (stop.get()) {
                    slots.release();
                    break;
                }
                pool.submit(() -> {
                    try {
                        HttpRequest req = buildRequest(base, location, parameter, passMarker, userMarker,
                                attempt.username, attempt.password);
                        if (req == null) {
                            Row row = new Row();
                            row.username = attempt.username;
                            row.password = attempt.password;
                            row.error = "could not inject credentials into the request.";
                            rows.add(row);
                            return;
                        }
                        Probe p = send(ctx, req);
                        sent.incrementAndGet();
                        Row row = classify(baseline, p, attempt.username, attempt.password);
                        boolean interesting = row.likelyHit || row.lockout;
                        if (interesting && p.exchange != null) {
                            try {
                                row.messageId = ctx.messages.register(p.exchange, "brute");
                            } catch (RuntimeException ignored) {
                            }
                        }
                        rows.add(row);
                        if (row.lockout) {
                            if (lockoutCount.incrementAndGet() >= 3 || (p.status != null && p.status == 429)) {
                                stop.set(true);
                            }
                        }
                        if (stopOnHit && row.likelyHit) {
                            stop.set(true);
                        }
                    } finally {
                        slots.release();
                    }
                });
            }
        } finally {
            pool.shutdown();
            try {
                pool.awaitTermination(30, TimeUnit.MINUTES);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                pool.shutdownNow();
            }
        }

        List<Row> all = new ArrayList<>(rows);
        List<Map<String, Object>> hits = new ArrayList<>();
        List<Map<String, Object>> lockouts = new ArrayList<>();
        Map<String, Cluster> clusters = new LinkedHashMap<>();
        for (Row row : all) {
            if (row.likelyHit && hits.size() < MAX_HITS_IN_RESULT) {
                hits.add(row.toMap());
            }
            if (row.lockout && lockouts.size() < 5) {
                lockouts.add(row.toMap());
            }
            String key = (row.status == null ? "err" : row.status.toString()) + ":" + row.length;
            Cluster c = clusters.get(key);
            if (c == null) {
                c = new Cluster(row.status, row.length);
                clusters.put(key, c);
            }
            c.count++;
            if (c.samples.size() < CLUSTER_SAMPLES) {
                c.samples.add(echo(row.password));
            }
            if (row.likelyHit) {
                c.likelyHit = true;
            }
        }

        List<Map<String, Object>> clusterList = new ArrayList<>();
        for (Cluster c : clusters.values()) {
            clusterList.add(c.toMap());
        }

        Map<String, Object> data = new LinkedHashMap<>();
        try {
            data.put("url", base.url());
        } catch (RuntimeException ignored) {
        }
        data.put("attempts_planned", plan.size());
        data.put("attempts_sent", sent.get());
        data.put("stopped_early", stop.get());
        data.put("wordlist", wordlistName == null ? "payloads" : wordlistName);
        data.put("usernames", usernames.size() == 1 && usernames.get(0) == null ? 0 : usernames.size());
        data.put("concurrency", concurrency);
        Map<String, Object> baseMap = new LinkedHashMap<>();
        baseMap.put("status", baseline.status);
        baseMap.put("length", baseline.length);
        baseMap.put("duration_ms", baseline.durationMs);
        data.put("baseline", baseMap);
        data.put("hit_count", hits.size());
        data.put("hits", hits);
        if (!lockouts.isEmpty()) {
            data.put("lockout_samples", lockouts);
        }
        data.put("clusters", clusterList);
        data.put("note", hits.isEmpty()
                ? "No likely success. Majority cluster is the failed-login fingerprint. "
                + "A hit is a different status/length, a token/JWT in the body, or a new Set-Cookie. "
                + "If the app locked out, lockout_samples is set. Raise max_attempts or try another username."
                : "Likely hit(s) below. Confirm with inspect_http_message on the message_id before reporting.");
        return ToolResult.ok(data);
    }

    private static HttpRequest buildRequest(HttpRequest base, String location, String parameter,
                                            String passMarker, String userMarker,
                                            String username, String password) {
        HttpRequest req = base;
        if (username != null && userMarker != null) {
            req = FuzzTools.injectMarker(req, userMarker, username);
            if (req == null) {
                return null;
            }
        } else if (username != null && userMarker == null) {
            HttpRequest injected = FuzzTools.inject(req, "json_body", "username", null, "replace", username);
            if (injected != null) {
                req = injected;
            }
        }
        if (passMarker != null) {
            return FuzzTools.injectMarker(req, passMarker, password);
        }
        return FuzzTools.inject(req, location, parameter, null, "replace", password);
    }

    private static Row classify(Probe baseline, Probe p, String username, String password) {
        Row row = new Row();
        row.username = username;
        row.password = password;
        row.status = p.status;
        row.length = p.length;
        row.durationMs = p.durationMs;
        row.error = p.error;
        if (p.error != null && p.status == null) {
            return row;
        }
        String body = p.body == null ? "" : p.body;
        String lower = body.toLowerCase();
        row.lockout = (p.status != null && p.status == 429) || containsAny(lower, LOCKOUT_SIGNATURES);
        if (row.lockout) {
            return row;
        }
        boolean failSig = containsAny(lower, FAIL_SIGNATURES);
        boolean hitSig = containsAny(lower, HIT_SIGNATURES) || p.setCookie;
        boolean statusChanged = baseline.status != null && p.status != null && !baseline.status.equals(p.status);
        boolean interestingStatus = p.status != null && ((p.status >= 200 && p.status < 400) || p.status == 401 || p.status == 403);
        int delta = Math.abs(p.length - baseline.length);
        boolean lengthShift = delta >= Math.max(HIT_LENGTH_DELTA, baseline.length / 4);

        if (hitSig && !failSig) {
            row.likelyHit = true;
            row.reason = p.setCookie ? "new Set-Cookie / token in body" : "success signature in body";
        } else if (statusChanged && interestingStatus && !failSig) {
            row.likelyHit = true;
            row.reason = "status " + baseline.status + " → " + p.status;
        } else if (lengthShift && !failSig) {
            row.likelyHit = true;
            row.reason = "length " + baseline.length + " → " + p.length + " without fail signature";
        }
        return row;
    }

    private static Probe send(ToolContext ctx, HttpRequest req) {
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
        out.exchange = rr;
        if (rr.hasResponse() && rr.response() != null) {
            HttpResponse resp = rr.response();
            out.status = (int) resp.statusCode();
            try {
                out.body = resp.bodyToString();
            } catch (RuntimeException e) {
                out.body = "";
            }
            out.length = out.body == null ? 0 : out.body.length();
            try {
                out.setCookie = resp.hasHeader("Set-Cookie") || (resp.cookies() != null && !resp.cookies().isEmpty());
            } catch (RuntimeException e) {
                try {
                    out.setCookie = resp.toString().toLowerCase().contains("set-cookie:");
                } catch (RuntimeException ignored) {
                }
            }
        } else {
            out.error = "no response";
        }
        return out;
    }

    private static String firstPresent(String raw, String explicit, String[] defaults) {
        if (explicit != null && !explicit.isEmpty()) {
            return explicit;
        }
        if (raw == null) {
            return null;
        }
        for (String m : defaults) {
            if (raw.contains(m)) {
                return m;
            }
        }
        return null;
    }

    private static boolean containsAny(String lower, String[] needles) {
        for (String n : needles) {
            if (lower.contains(n)) {
                return true;
            }
        }
        return false;
    }

    private static String echo(String s) {
        if (s == null) {
            return null;
        }
        return s.length() <= PAYLOAD_ECHO_MAX ? s : s.substring(0, PAYLOAD_ECHO_MAX) + "\u2026";
    }

    private static void sleep(int ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static Map<String, Object> mapOf(String k, Object v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put(k, v);
        return m;
    }

    private static final class Attempt {
        final String username;
        final String password;

        Attempt(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }

    private static final class Probe {
        Integer status;
        int length;
        long durationMs;
        String body = "";
        boolean setCookie;
        String error;
        HttpRequestResponse exchange;
    }

    private static final class Row {
        String username;
        String password;
        Integer status;
        int length;
        long durationMs;
        String error;
        boolean likelyHit;
        boolean lockout;
        String reason;
        Integer messageId;

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            if (username != null) {
                m.put("username", username);
            }
            m.put("password", echo(password));
            if (error != null) {
                m.put("error", error);
                return m;
            }
            m.put("status", status);
            m.put("length", length);
            m.put("duration_ms", durationMs);
            if (likelyHit) {
                m.put("likely_hit", true);
                m.put("reason", reason);
            }
            if (lockout) {
                m.put("lockout", true);
            }
            if (messageId != null) {
                m.put("message_id", messageId);
            }
            return m;
        }
    }

    private static final class Cluster {
        final Integer status;
        final int length;
        int count;
        boolean likelyHit;
        final List<String> samples = new ArrayList<>();

        Cluster(Integer status, int length) {
            this.status = status;
            this.length = length;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("status", status);
            m.put("length", length);
            m.put("count", count);
            m.put("sample_passwords", samples);
            if (likelyHit) {
                m.put("likely_hit", true);
            }
            return m;
        }
    }
}
