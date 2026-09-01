/*
 * Organizer tools: list rows currently stored in the Organizer.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.organizer.OrganizerItem;

public final class OrganizerTools {

    private OrganizerTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "list_organizer_entries",
                "List Organizer rows (id, method, url, status, item status). args: max_results?.",
                false,
                Schema.object().prop("max_results", "integer", "Maximum rows (default 200).").build(),
                OrganizerTools::listEntries));
    }

    private static ToolResult listEntries(Map<String, Object> args, ToolContext ctx) {
        int limit = Tools.intOr(args, "max_results", 200);
        List<Map<String, Object>> items = new ArrayList<>();
        List<OrganizerItem> organizerItems;
        try {
            organizerItems = ctx.api.organizer().items();
        } catch (RuntimeException e) {
            return ToolResult.error("Organizer unavailable: " + e.getMessage());
        }
        for (OrganizerItem item : organizerItems) {
            if (items.size() >= limit) {
                break;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", item.id());
            try {
                m.put("method", item.request().method());
                m.put("url", item.request().url());
            } catch (RuntimeException ignored) {
            }
            m.put("status", item.hasResponse() && item.response() != null ? (int) item.response().statusCode() : null);
            try {
                m.put("item_status", item.status() == null ? null : item.status().toString());
            } catch (RuntimeException ignored) {
            }
            items.add(m);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("total", organizerItems.size());
        data.put("returned", items.size());
        data.put("items", items);
        return ToolResult.ok(data);
    }
}
