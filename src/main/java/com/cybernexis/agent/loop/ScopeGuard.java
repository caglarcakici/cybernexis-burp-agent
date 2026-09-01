/*
 * Optional safety gate: blocks action tools that would send traffic to a host
 * that is not in Burp's target scope. add_to_scope is always allowed so the
 * agent can bring a target in-scope first (with the user's approval).
 */
package com.cybernexis.agent.loop;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import burp.api.montoya.MontoyaApi;

public final class ScopeGuard {

    /** Tools that generate outbound traffic to a target derived from args. */
    private static final Set<String> NETWORK_TOOLS = new HashSet<>(Arrays.asList(
            "send_request", "crawl_and_audit", "audit_request", "fuzz_request", "brute_force"));

    private ScopeGuard() {
    }

    /**
     * @return null if the call is allowed, otherwise a message explaining the block.
     */
    public static String check(String tool, Map<String, Object> args, MontoyaApi api) {
        if (tool == null || !NETWORK_TOOLS.contains(tool) || args == null) {
            return null;
        }
        String url = targetUrl(args);
        if (url == null) {
            // Can't determine a target (e.g. request_id only) — let the tool proceed.
            return null;
        }
        try {
            if (api.scope().isInScope(url)) {
                return null;
            }
        } catch (RuntimeException e) {
            return null;
        }
        return "Blocked: " + url + " is not in Burp's target scope. "
                + "Add it with add_to_scope first, or disable scope enforcement in Settings.";
    }

    private static String targetUrl(Map<String, Object> args) {
        Object url = args.get("url");
        if (url instanceof String && !((String) url).trim().isEmpty()) {
            return ((String) url).trim();
        }
        Object host = args.get("host");
        if (host instanceof String && !((String) host).trim().isEmpty()) {
            String h = ((String) host).trim();
            if (h.startsWith("http://") || h.startsWith("https://")) {
                return h;
            }
            return "https://" + h;
        }
        return null;
    }
}
