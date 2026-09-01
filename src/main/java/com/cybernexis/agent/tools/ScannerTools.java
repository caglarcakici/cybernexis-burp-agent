/*
 * Scanner tools: start audits and crawls, list scan tasks started this session,
 * and report built-in audit configurations. Pause/resume and custom-check
 * enumeration are not exposed by the Montoya API and report as unsupported.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.ScanTask;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.http.message.requests.HttpRequest;

public final class ScannerTools {

    private ScannerTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "list_scan_tasks",
                "List scan tasks started this session (task_id, status, requests, errors).",
                false,
                ToolDescriptor.emptyParams(),
                ScannerTools::listScanTasks));

        registry.register(new ToolDescriptor(
                "get_scan_config",
                "Get available built-in audit configurations. args: config_name?.",
                false,
                Schema.object().prop("config_name", "string", "Optional specific config name.").build(),
                ScannerTools::getScanConfig));

        registry.register(new ToolDescriptor(
                "audit_request",
                "Actively scan specific requests (no crawl). args: targets[] (message ids or urls), passive?.",
                true,
                Schema.object()
                        .arrayProp("targets", "string", "Stored message ids or URLs to audit.")
                        .prop("passive", "boolean", "Use passive checks instead of active (default false).")
                        .require("targets")
                        .build(),
                ScannerTools::auditRequest));

        registry.register(new ToolDescriptor(
                "crawl_and_audit",
                "Crawl a URL to discover content (audit runs on discovered in-scope items). args: url (required).",
                true,
                Schema.object().prop("url", "string", "Seed URL to crawl.").require("url").build(),
                ScannerTools::crawlAndAudit));

        registry.register(new ToolDescriptor(
                "pause_task",
                "Pause a scan task. Not supported by the Montoya API.",
                true,
                Schema.object().prop("task_id", "string", "Task id.").build(),
                (a, c) -> ToolResult.error("pause_task is not supported by the Montoya API (tasks can only be deleted).")));

        registry.register(new ToolDescriptor(
                "resume_task",
                "Resume a scan task. Not supported by the Montoya API.",
                true,
                Schema.object().prop("task_id", "string", "Task id.").build(),
                (a, c) -> ToolResult.error("resume_task is not supported by the Montoya API.")));
    }

    private static ToolResult listScanTasks(Map<String, Object> args, ToolContext ctx) {
        List<Map<String, Object>> tasks = new ArrayList<>();
        for (Map.Entry<String, ScanTask> e : ctx.scanTasks().entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("task_id", e.getKey());
            ScanTask task = e.getValue();
            try {
                m.put("status", task.statusMessage());
            } catch (RuntimeException ex) {
                m.put("status", "unknown");
            }
            try {
                m.put("requests", task.requestCount());
                m.put("errors", task.errorCount());
            } catch (RuntimeException ignored) {
            }
            tasks.add(m);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("tasks", tasks);
        return ToolResult.ok(data);
    }

    private static ToolResult getScanConfig(Map<String, Object> args, ToolContext ctx) {
        List<String> configs = new ArrayList<>();
        for (BuiltInAuditConfiguration c : BuiltInAuditConfiguration.values()) {
            configs.add(c.name());
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("built_in_audit_configurations", configs);
        String requested = Tools.str(args, "config_name");
        if (requested != null) {
            data.put("matched", configs.contains(requested.toUpperCase()) ? requested.toUpperCase() : null);
        }
        return ToolResult.ok(data);
    }

    private static ToolResult auditRequest(Map<String, Object> args, ToolContext ctx) {
        List<String> targets = Tools.strList(args, "targets");
        if (targets.isEmpty()) {
            return ToolResult.error("targets is required.");
        }
        boolean passive = Tools.boolOr(args, "passive", false);
        AuditConfiguration cfg = AuditConfiguration.auditConfiguration(passive
                ? BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                : BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);

        Audit audit;
        try {
            audit = ctx.api.scanner().startAudit(cfg);
        } catch (RuntimeException e) {
            return ToolResult.error("Could not start audit: " + e.getMessage());
        }

        ctx.messages.refresh(ctx.api);
        List<Object> added = new ArrayList<>();
        for (String target : targets) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("target", target);
            try {
                HttpRequest request = resolveTarget(target, ctx);
                if (request == null) {
                    r.put("ok", false);
                    r.put("error", "could not resolve target");
                } else {
                    audit.addRequest(request);
                    r.put("ok", true);
                }
            } catch (RuntimeException e) {
                r.put("ok", false);
                r.put("error", e.getMessage());
            }
            added.add(r);
        }

        String taskId = ctx.registerScanTask(audit);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("task_id", taskId);
        data.put("mode", passive ? "passive" : "active");
        data.put("targets", added);
        return ToolResult.ok(data);
    }

    private static ToolResult crawlAndAudit(Map<String, Object> args, ToolContext ctx) {
        String url = Tools.interp(ctx, Tools.str(args, "url"));
        if (url == null) {
            return ToolResult.error("url is required.");
        }
        Crawl crawl;
        try {
            crawl = ctx.api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(url));
        } catch (RuntimeException e) {
            return ToolResult.error("Could not start crawl: " + e.getMessage());
        }
        String taskId = ctx.registerScanTask(crawl);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("task_id", taskId);
        data.put("seed_url", url);
        data.put("note", "Crawl started. Audit discovered items with audit_request, or configure a crawl-and-audit task in the Burp UI.");
        return ToolResult.ok(data);
    }

    private static HttpRequest resolveTarget(String target, ToolContext ctx) {
        try {
            int id = Integer.parseInt(target.trim());
            MessageStore.Entry entry = ctx.messages.get(id);
            if (entry != null) {
                return entry.message.request();
            }
        } catch (NumberFormatException ignored) {
            // not an id; treat as URL
        }
        if (target.startsWith("http://") || target.startsWith("https://")) {
            return HttpRequest.httpRequestFromUrl(target);
        }
        return null;
    }
}
