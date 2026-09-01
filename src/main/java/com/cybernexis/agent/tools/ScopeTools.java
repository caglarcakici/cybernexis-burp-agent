/*
 * Scope tools: inspect the derived in-scope origins and include/exclude URL
 * prefixes. Montoya exposes include/exclude/isInScope but not enumeration, so
 * inspect_scope derives the list from the sitemap and proxy history.
 */
package com.cybernexis.agent.tools;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public final class ScopeTools {

    private ScopeTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "inspect_scope",
                "List the origins currently in the Burp target scope (derived from sitemap and proxy history).",
                false,
                ToolDescriptor.emptyParams(),
                ScopeTools::inspectScope));

        registry.register(new ToolDescriptor(
                "add_to_scope",
                "Add URL prefixes to the target scope. Enables active tools for those hosts. Sends no traffic. args: prefixes[].",
                true,
                Schema.object().arrayProp("prefixes", "string", "URL prefixes to include").require("prefixes").build(),
                ScopeTools::addToScope));

        registry.register(new ToolDescriptor(
                "remove_from_scope",
                "Remove URL prefixes from the target scope. args: prefixes[].",
                true,
                Schema.object().arrayProp("prefixes", "string", "URL prefixes to exclude").require("prefixes").build(),
                ScopeTools::removeFromScope));
    }

    private static ToolResult inspectScope(Map<String, Object> args, ToolContext ctx) {
        Set<String> origins = new LinkedHashSet<>();
        try {
            for (HttpRequestResponse hrr : ctx.api.siteMap().requestResponses()) {
                collectIfInScope(ctx, hrr.request().url(), origins);
            }
        } catch (RuntimeException ignored) {
        }
        try {
            for (ProxyHttpRequestResponse phrr : ctx.api.proxy().history()) {
                collectIfInScope(ctx, phrr.finalRequest().url(), origins);
            }
        } catch (RuntimeException ignored) {
        }
        String focus = ctx.focusHost();
        Map<String, Object> data = new LinkedHashMap<>();
        if (focus != null) {
            Set<String> focused = new LinkedHashSet<>();
            int others = 0;
            for (String origin : origins) {
                if (Focus.urlMatches(origin, focus) || Focus.hostMatches(Focus.hostOf(origin), focus)) {
                    focused.add(origin);
                } else {
                    others++;
                }
            }
            data.put("task_focus_host", focus);
            data.put("in_scope_origins", focused);
            data.put("other_in_scope_origins", others);
            data.put("note", "Filtered to this task's focus host. "
                    + others + " other in-scope origin(s) from the Burp project are hidden. "
                    + "Name another host in the chat if you want to switch focus.");
        } else {
            data.put("in_scope_origins", origins);
            data.put("note", "Derived by testing known URLs against Burp scope; may be incomplete if nothing has been visited yet.");
        }
        return ToolResult.ok(data);
    }

    private static void collectIfInScope(ToolContext ctx, String url, Set<String> origins) {
        try {
            if (ctx.api.scope().isInScope(url)) {
                origins.add(originOf(url));
            }
        } catch (RuntimeException ignored) {
        }
    }

    private static ToolResult addToScope(Map<String, Object> args, ToolContext ctx) {
        List<String> prefixes = Tools.strList(args, "prefixes");
        if (prefixes.isEmpty()) {
            return ToolResult.error("No prefixes provided.");
        }
        for (String p : prefixes) {
            ctx.api.scope().includeInScope(p);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("included", prefixes);
        return ToolResult.ok(data);
    }

    private static ToolResult removeFromScope(Map<String, Object> args, ToolContext ctx) {
        List<String> prefixes = Tools.strList(args, "prefixes");
        if (prefixes.isEmpty()) {
            return ToolResult.error("No prefixes provided.");
        }
        for (String p : prefixes) {
            ctx.api.scope().excludeFromScope(p);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("excluded", prefixes);
        return ToolResult.ok(data);
    }

    private static String originOf(String url) {
        try {
            java.net.URI u = java.net.URI.create(url);
            StringBuilder o = new StringBuilder();
            o.append(u.getScheme()).append("://").append(u.getHost());
            if (u.getPort() > 0) {
                o.append(':').append(u.getPort());
            }
            return o.toString();
        } catch (RuntimeException e) {
            return url;
        }
    }
}
