/*
 * Short testing playbooks that seed a task's system addendum. Each one is a
 * methodology checklist mapped to Cybernexis tools — not a payload catalog.
 */
package com.cybernexis.agent.ui;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class Playbooks {

    public static final String GROUP = "Playbook";

    private Playbooks() {
    }

    public static List<TaskTemplates.Template> all() {
        List<TaskTemplates.Template> list = new ArrayList<>();
        list.add(fastChecking());
        list.add(idor());
        list.add(apiSecurity());
        list.add(jwt());
        list.add(oauth());
        list.add(ssrf());
        list.add(businessLogic());
        list.add(graphql());
        list.add(xss());
        list.add(sqli());
        list.add(openRedirectHpp());
        list.add(reporting());
        return list;
    }

    public static TaskTemplates.Template byName(String name) {
        if (name == null) {
            return null;
        }
        for (TaskTemplates.Template t : all()) {
            if (name.equals(t.name)) {
                return t;
            }
        }
        return null;
    }

    /**
     * Pick the most specific playbook whose keywords appear in the user text
     * (or a URL). Returns null when nothing matches.
     */
    public static TaskTemplates.Template match(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String hay = text.toLowerCase(Locale.ROOT);
        TaskTemplates.Template best = null;
        int bestScore = 0;
        for (TaskTemplates.Template t : all()) {
            int score = 0;
            for (String kw : t.keywords) {
                if (kw != null && !kw.isEmpty() && hay.contains(kw.toLowerCase(Locale.ROOT))) {
                    score += kw.length();
                }
            }
            if (score > bestScore) {
                bestScore = score;
                best = t;
            }
        }
        return bestScore > 0 ? best : null;
    }

    public static boolean isPlaybook(String templateName) {
        return byName(templateName) != null;
    }

    public static boolean alreadyApplied(String addendum, TaskTemplates.Template playbook) {
        return addendum != null && playbook != null && addendum.contains("PLAYBOOK: " + playbook.name);
    }

    /** True when the user is asking to test/analyze rather than just inspect Burp state. */
    public static boolean looksLikeTestIntent(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        String t = text.toLowerCase(Locale.ROOT);
        if (t.contains("what's in scope") || t.contains("what is in scope")
                || t.contains("list sitemap") || t.contains("list the sitemap")
                || t.contains("list issues") || t.contains("inspect issue")
                || t.contains("list scan")) {
            return false;
        }
        String[] phrases = {
                "analyze", "analyse", "test this", "test the", "test for", "pentest",
                "audit", "fuzz", "check this", "check for", "vulnerability", "vulnerabilities",
                "güvenlik", "test et", "incele", "analiz", "start testing", "run a test", "probe"
        };
        for (String p : phrases) {
            if (t.contains(p)) {
                return true;
            }
        }
        return t.contains("https://") || t.contains("http://");
    }

    public static TaskTemplates.Template fromHintName(String name) {
        return byName(name);
    }

    private static TaskTemplates.Template pb(String name, String[] keywords, String... lines) {
        return new TaskTemplates.Template(name, GROUP, String.join("\n", lines), keywords);
    }

    private static final String RULES = String.join("\n",
            "PLAYBOOK RULES",
            "- Use EXACT catalog tool names. Read-only first.",
            "- Stay on FOCUS HOST. Confirm with stored message_id evidence, then create_issue.",
            "- Keep fuzz_request payloads[] short and hypothesis-driven. Do not paste wordlists (use brute_force for login).",
            "- Final write-up: ## Finding / ## Evidence / ## Recommendation.");

    private static TaskTemplates.Template fastChecking() {
        return pb("Fast checking",
                new String[]{"fast checking", "fast check", "checklist", "quick triage", "first pass"},
                "PLAYBOOK: Fast checking",
                "First-pass triage of the focus host. Do not start a full attack.",
                "1. inspect_scope, list_sitemap, list_issues, list_memory.",
                "2. search_http_messages for login, /api, graphql, callback, upload, admin.",
                "3. inspect_http_message on 2-4 interesting items; scan_tokens on each.",
                "4. remember login_path, csrf_field, session_cookie, tech when you learn them.",
                "5. Stop with a prioritized list of what to test next and which playbook fits.",
                "Do not fuzz, brute_force, audit, or send new traffic unless the user asks.",
                RULES);
    }

    private static TaskTemplates.Template idor() {
        return pb("IDOR / BOLA",
                new String[]{"idor", "bola", "insecure direct object", "object-level", "broken object"},
                "PLAYBOOK: IDOR / BOLA",
                "Test whether object identifiers in URLs, bodies, or tokens authorize incorrectly.",
                "1. list_sitemap + search_http_messages for id, uuid, user, account, order, document, /me.",
                "2. inspect_http_message; scan_tokens. Note which IDs belong to the current user.",
                "3. remember interesting object endpoints.",
                "4. send_request with edits that swap only the object id (keep the same session).",
                "5. fuzz_request on the id parameter with a short set of neighboring or guessed IDs.",
                "6. compare_http_messages(baseline vs variant). Access is broken if another object's data returns 200 with a different body.",
                "7. Repeat with a second role/token if the user provides one (Authorization / cookie edits).",
                "Also try: missing id, id=0, nested resource ids, batch endpoints that accept arrays of ids.",
                RULES);
    }

    private static TaskTemplates.Template apiSecurity() {
        return pb("API security",
                new String[]{"api security", "owasp api", "mass assignment", "bfla", "excessive data", "verb tampering"},
                "PLAYBOOK: API security",
                "OWASP API-oriented pass: BOLA, auth, data exposure, BFLA, mass assignment, verb tampering.",
                "1. list_sitemap + search_http_messages for /api, /v1, /v2, /graphql, swagger, openapi.",
                "2. inspect_http_message on representative calls; scan_tokens for JWT/API keys.",
                "3. BOLA: ID swap on object URLs (same as IDOR playbook) via send_request edits.",
                "4. BFLA: send_request to admin/debug paths with the current (non-admin) token.",
                "5. Mass assignment: add unexpected JSON fields (role, admin, price, verified) via body edits; compare_http_messages.",
                "6. Verb tampering: retry the same path with GET/POST/PUT/PATCH/DELETE (method edit).",
                "7. Rate / lockout: prefer brute_force on login only; do not flood other endpoints.",
                "8. Excessive data: compare list vs detail responses for extra fields.",
                RULES);
    }

    private static TaskTemplates.Template jwt() {
        return pb("JWT",
                new String[]{"jwt", "json web token", "bearer token", "jws", "jwks"},
                "PLAYBOOK: JWT",
                "Use the Token Map; do not invent tokens. Live values expire — re-extract before sending.",
                "1. scan_tokens on the login or API response. extract_from_response preset=jwt into a variable if needed.",
                "2. inspect_http_message and note header vs body vs cookie placement.",
                "3. remember session_cookie / tech if JWT is how the API authenticates.",
                "4. send_request variants (one change at a time) via header/cookie edits:",
                "   missing token; truncated token; expired/invalid token if you have one; token from a different user if provided.",
                "5. compare_http_messages against the baseline. A 200 with data on a broken token is a finding.",
                "6. Do not brute-force secrets. Do not paste third-party JWT attack tools. encode_decode is for inspecting parts you already have.",
                RULES);
    }

    private static TaskTemplates.Template oauth() {
        return pb("OAuth / OIDC",
                new String[]{"oauth", "oidc", "openid", "redirect_uri", "authorization code", "auth code"},
                "PLAYBOOK: OAuth / OIDC",
                "Map the authorization code flow with stored messages. Do not phish or stand up a fake IdP.",
                "1. search_http_messages for authorize, oauth, openid, callback, redirect_uri, client_id, state, code, nonce.",
                "2. inspect_http_message on /authorize and the callback. extract_from_response for state and code.",
                "3. Check: state present and bound; redirect_uri strictly matched; code single-use.",
                "4. send_request only against in-scope callback/authorize URLs the app already uses.",
                "   Probe redirect_uri / state mismatch by editing query params; compare_http_messages.",
                "5. Open-redirect on redirect_uri is in-scope for this playbook; chain only inside the focus host.",
                RULES);
    }

    private static TaskTemplates.Template ssrf() {
        return pb("SSRF",
                new String[]{"ssrf", "server-side request", "metadata endpoint", "out-of-band", "collaborator"},
                "PLAYBOOK: SSRF",
                "Look for server-fetched URLs. Confirm with Collaborator or timing — do not scan the internet.",
                "1. search_http_messages for url, uri, webhook, callback, fetch, image, pdf, proxy, dest, target, path=http.",
                "2. inspect_http_message; remember the parameter name.",
                "3. create_collaborator_payloads; put that hostname into the suspect parameter via send_request or fuzz_request.",
                "4. poll_for_collaborator_interactions. An interaction is evidence.",
                "5. If no OOB: fuzz_request and watch timing_anomaly (slow responses vs baseline).",
                "6. Stay on the application parameter. Do not target unrelated third-party hosts.",
                RULES);
    }

    private static TaskTemplates.Template businessLogic() {
        return pb("Business logic",
                new String[]{"business logic", "workflow bypass", "price manipulation", "coupon", "quantity", "checkout"},
                "PLAYBOOK: Business logic",
                "Abuse application rules, not injection. Map the state machine from the sitemap first.",
                "1. list_sitemap; search_http_messages for cart, checkout, order, pay, coupon, discount, refund, invite, transfer.",
                "2. Sketch the intended step order from stored requests (inspect_http_message).",
                "3. send_request: skip a step (replay confirm without pay); replay a one-time action; change quantity/price/currency fields.",
                "4. compare_http_messages after each single change.",
                "5. If a limit looks racy, say so and stage_in_intruder — do not invent a parallel send tool.",
                "6. Tenant/role: swap account or org ids while keeping the current session (IDOR overlap).",
                RULES);
    }

    private static TaskTemplates.Template graphql() {
        return pb("GraphQL",
                new String[]{"graphql", "/graphql", "introspection", "__schema", "gql"},
                "PLAYBOOK: GraphQL",
                "Treat GraphQL as one endpoint with many operations. Prefer send_request with JSON body edits.",
                "1. search_http_messages for graphql, /gql, application/graphql.",
                "2. inspect_http_message; remember the path. scan_tokens on the response.",
                "3. If introspection appears enabled, request the schema via send_request and summarize types/queries/mutations.",
                "4. Authorization: replay queries/mutations that return other users' objects (nested IDs, node(id:)).",
                "5. Batching / alias abuse: only a few operations — look for missing per-operation auth, not DoS.",
                "6. Injection: fuzz_request on a single variable (timing_anomaly / error_signature). Keep payloads few.",
                RULES);
    }

    private static TaskTemplates.Template xss() {
        return pb("XSS",
                new String[]{"xss", "cross-site scripting", "reflected xss", "stored xss", "dom xss"},
                "PLAYBOOK: XSS",
                "Find reflection first; do not drop exploit frameworks or large payload packs.",
                "1. search_http_messages for query/body params that echo into HTML (search, q, name, comment, message, error).",
                "2. inspect_http_message; note content-type and encoding.",
                "3. fuzz_request on that parameter; the tool flags payload reflected. Inspect those message_ids.",
                "4. Distinguish reflected vs stored (does a later page include the value?) via list_sitemap / a follow-up send_request GET.",
                "5. create_issue only when the response context shows the value is not safely encoded. Quote the evidence snippet.",
                RULES);
    }

    private static TaskTemplates.Template sqli() {
        return pb("SQLi",
                new String[]{"sqli", "sql injection", "nosql", "sqlmap"},
                "PLAYBOOK: SQLi",
                "Detection only with Burp tools. Do not call sqlmap or dump databases.",
                "1. search_http_messages for parameterized endpoints (id, search, filter, sort, q) and JSON filters.",
                "2. inspect_http_message; pick one parameter.",
                "3. fuzz_request: a short syntax-probe list. Watch error_signature, status change, length change, timing_anomaly.",
                "4. Blind time-based: timing_anomaly vs baseline is enough to report as suspected blind SQLi — do not extract rows.",
                "5. OOB: create_collaborator_payloads only if the app might trigger a DB network call; then poll_for_collaborator_interactions.",
                "6. create_issue with the probe that changed behaviour and the message_id. Stop after confirmation.",
                RULES);
    }

    private static TaskTemplates.Template openRedirectHpp() {
        return pb("Open redirect / HPP",
                new String[]{"open redirect", "open-redirect", "parameter pollution", "hpp", "redirect_uri", "next=", "returnurl"},
                "PLAYBOOK: Open redirect / HPP",
                "Redirect and duplicate-parameter confusion. Keep destinations in-scope or clearly documented.",
                "1. search_http_messages for redirect, next, url, return, returnUrl, dest, continue, callback, goto.",
                "2. inspect_http_message; send_request with edited redirect targets (relative vs absolute, same-host vs other-host).",
                "3. A finding is a 3xx Location (or JS redirect) the app should not have allowed. Quote Location.",
                "4. HPP: send_request with duplicate query keys (a=1&a=2) or mixed query+body; compare_http_messages.",
                "5. If OAuth is in play, prefer the OAuth playbook for redirect_uri — this playbook covers generic redirects.",
                RULES);
    }

    private static TaskTemplates.Template reporting() {
        return pb("Reporting",
                new String[]{"write a report", "engagement report", "executive summary", "reporting playbook"},
                "PLAYBOOK: Reporting",
                "Turn current Burp evidence into a client-ready write-up. No new attacks.",
                "1. list_issues (and list_scan_issues). Group by severity and type.",
                "2. inspect_issue + inspect_http_message for evidence. Drop likely false positives with a reason.",
                "3. create_issue / edit nothing unless the user asks to file a missing finding.",
                "4. Answer with:",
                "   # Executive summary (risk-led, short)",
                "   # Findings table (title, severity, affected URL, evidence message_id)",
                "   For each confirmed issue: Summary, Evidence, Impact, Recommendation, Retest notes.",
                "5. Redact secrets in quotes. Do not invent CVSS if you lack data — say confidence instead.",
                RULES);
    }
}
