/*
 * Collaborator tools: generate OOB payloads and poll for / inspect interactions.
 * All calls share one Collaborator client created lazily in the ToolContext.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;

public final class CollaboratorTools {

    private CollaboratorTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "create_collaborator_payloads",
                "Generate Burp Collaborator OOB payloads. args: count? (default 1).",
                true,
                Schema.object().prop("count", "integer", "Number of payloads (default 1).").build(),
                CollaboratorTools::createPayloads));

        registry.register(new ToolDescriptor(
                "poll_for_collaborator_interactions",
                "Poll for Collaborator interactions received by this session's client. args: max_results?.",
                false,
                Schema.object().prop("max_results", "integer", "Maximum interactions (default 50).").build(),
                CollaboratorTools::poll));

        registry.register(new ToolDescriptor(
                "inspect_collaborator_interaction",
                "Get details of one Collaborator interaction by id. args: interaction_id (required).",
                false,
                Schema.object().prop("interaction_id", "string", "Interaction id.").require("interaction_id").build(),
                CollaboratorTools::inspect));
    }

    private static ToolResult createPayloads(Map<String, Object> args, ToolContext ctx) {
        int count = Math.max(1, Tools.intOr(args, "count", 1));
        List<String> payloads = new ArrayList<>();
        try {
            for (int i = 0; i < count; i++) {
                CollaboratorPayload p = ctx.collaborator().generatePayload();
                payloads.add(p.toString());
            }
        } catch (RuntimeException e) {
            return ToolResult.error("Collaborator disabled or unavailable: " + e.getMessage());
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("payloads", payloads);
        return ToolResult.ok(data);
    }

    private static ToolResult poll(Map<String, Object> args, ToolContext ctx) {
        if (!ctx.hasCollaborator()) {
            return ToolResult.error("No Collaborator client yet. Call create_collaborator_payloads first.");
        }
        int limit = Tools.intOr(args, "max_results", 50);
        List<Interaction> interactions;
        try {
            interactions = ctx.collaborator().getAllInteractions();
        } catch (RuntimeException e) {
            return ToolResult.error("Poll failed: " + e.getMessage());
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Interaction it : interactions) {
            if (out.size() >= limit) {
                break;
            }
            out.add(summarize(it));
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("total", interactions.size());
        data.put("returned", out.size());
        data.put("interactions", out);
        return ToolResult.ok(data);
    }

    private static ToolResult inspect(Map<String, Object> args, ToolContext ctx) {
        String id = Tools.str(args, "interaction_id");
        if (id == null) {
            return ToolResult.error("interaction_id is required.");
        }
        if (!ctx.hasCollaborator()) {
            return ToolResult.error("No Collaborator client yet.");
        }
        for (Interaction it : ctx.collaborator().getAllInteractions()) {
            if (String.valueOf(it.id()).equals(id)) {
                return ToolResult.ok(summarize(it));
            }
        }
        return ToolResult.error("No interaction with id " + id + ".");
    }

    private static Map<String, Object> summarize(Interaction it) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", String.valueOf(it.id()));
        try {
            m.put("type", it.type() == null ? null : it.type().name());
        } catch (RuntimeException ignored) {
        }
        try {
            m.put("time", String.valueOf(it.timeStamp()));
        } catch (RuntimeException ignored) {
        }
        try {
            m.put("client_ip", it.clientIp() == null ? null : it.clientIp().getHostAddress());
        } catch (RuntimeException ignored) {
        }
        it.dnsDetails().ifPresent(d -> m.put("dns_query_type", String.valueOf(d.queryType())));
        it.httpDetails().ifPresent(d -> m.put("http_protocol", String.valueOf(d.protocol())));
        return m;
    }
}
