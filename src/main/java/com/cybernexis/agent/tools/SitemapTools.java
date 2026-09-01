/*
 * Sitemap tools: list items in Burp's site map with method, url and status.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.http.message.HttpRequestResponse;

public final class SitemapTools {

    private static final int DEFAULT_LIMIT = 200;

    private SitemapTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "list_sitemap",
                "List sitemap items (method, url, status). args: max_results?, url_contains?.",
                false,
                Schema.object()
                        .prop("max_results", "integer", "Maximum items to return (default 200).")
                        .prop("url_contains", "string", "Only include items whose URL contains this substring.")
                        .build(),
                SitemapTools::listSitemap));
    }

    private static ToolResult listSitemap(Map<String, Object> args, ToolContext ctx) {
        int limit = Tools.intOr(args, "max_results", DEFAULT_LIMIT);
        String filter = Tools.str(args, "url_contains");
        List<Map<String, Object>> items = new ArrayList<>();
        int total = 0;
        for (HttpRequestResponse hrr : ctx.api.siteMap().requestResponses()) {
            String url;
            String method;
            try {
                url = hrr.request().url();
                method = hrr.request().method();
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
            m.put("method", method);
            m.put("url", url);
            m.put("status", hrr.hasResponse() && hrr.response() != null ? (int) hrr.response().statusCode() : null);
            items.add(m);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("total_matched", total);
        data.put("returned", items.size());
        data.put("items", items);
        if (ctx.focusHost() != null) {
            data.put("task_focus_host", ctx.focusHost());
            data.put("note", "Restricted to host " + ctx.focusHost() + " (www. included). Sibling subdomains are excluded.");
        }
        return ToolResult.ok(data);
    }
}
