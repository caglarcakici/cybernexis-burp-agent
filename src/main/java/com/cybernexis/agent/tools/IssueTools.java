/*
 * Issue tools: list and inspect audit issues, and create custom issues. Issues
 * are addressed by their index in the current sitemap issue list (issue_id).
 * Edit/delete are not exposed by the Montoya API and report as unsupported.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public final class IssueTools {

    private static final int DETAIL_MAX = 8000;

    private IssueTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "list_issues",
                "List audit issues with issue_id, name, severity, confidence, base_url. Also returns exact severity_counts (use these for totals; do not estimate). args: severity?, url_contains?.",
                false,
                Schema.object()
                        .prop("severity", "string", "Filter: HIGH|MEDIUM|LOW|INFORMATION.")
                        .prop("url_contains", "string", "Only issues whose base_url contains this substring.")
                        .build(),
                IssueTools::listIssues));

        registry.register(new ToolDescriptor(
                "list_scan_issues",
                "List issues produced by scans (same set as list_issues, includes exact severity_counts). args: severity?.",
                false,
                Schema.object().prop("severity", "string", "Filter by severity.").build(),
                IssueTools::listIssues));

        registry.register(new ToolDescriptor(
                "inspect_issue",
                "Get full detail + evidence for one issue by issue_id. args: issue_id (required).",
                false,
                Schema.object().prop("issue_id", "integer", "Index from list_issues.").require("issue_id").build(),
                IssueTools::inspectIssue));

        registry.register(new ToolDescriptor(
                "list_issue_definitions",
                "List distinct issue definitions present in the current issues. Montoya cannot enumerate all built-ins.",
                false,
                ToolDescriptor.emptyParams(),
                IssueTools::listDefinitions));

        registry.register(new ToolDescriptor(
                "create_issue",
                "Create a custom audit issue. args: name (required), base_url (required), severity, confidence, detail?, remediation?, request_id?.",
                true,
                Schema.object()
                        .prop("name", "string", "Issue name.")
                        .prop("base_url", "string", "Base URL for the issue.")
                        .prop("severity", "string", "HIGH|MEDIUM|LOW|INFORMATION (default INFORMATION).")
                        .prop("confidence", "string", "CERTAIN|FIRM|TENTATIVE (default TENTATIVE).")
                        .prop("detail", "string", "Detailed description.")
                        .prop("remediation", "string", "Remediation advice.")
                        .prop("request_id", "integer", "Stored message id to attach as evidence.")
                        .require("name", "base_url")
                        .build(),
                IssueTools::createIssue));

        registry.register(new ToolDescriptor(
                "edit_issue",
                "Edit an existing issue. Not supported by the Montoya API.",
                true,
                Schema.object().prop("issue_id", "integer", "Issue index.").build(),
                (a, c) -> ToolResult.error("edit_issue is not supported by the Montoya API. Create a new issue instead.")));

        registry.register(new ToolDescriptor(
                "delete_issue",
                "Delete an issue. Not supported by the Montoya API.",
                true,
                Schema.object().prop("issue_id", "integer", "Issue index.").build(),
                (a, c) -> ToolResult.error("delete_issue is not supported by the Montoya API.")));
    }

    private static ToolResult listIssues(Map<String, Object> args, ToolContext ctx) {
        String severityFilter = Tools.str(args, "severity");
        String urlFilter = Tools.str(args, "url_contains");
        String focus = ctx.focusHost();
        List<AuditIssue> issues;
        try {
            issues = ctx.api.siteMap().issues();
        } catch (RuntimeException e) {
            return ToolResult.error("Issues unavailable: " + e.getMessage());
        }
        List<Map<String, Object>> out = new ArrayList<>();
        Map<String, Integer> severityCounts = new LinkedHashMap<>();
        for (AuditIssueSeverity s : AuditIssueSeverity.values()) {
            severityCounts.put(s.name(), 0);
        }
        int hidden = 0;
        for (int i = 0; i < issues.size(); i++) {
            AuditIssue issue = issues.get(i);
            String base = issue.baseUrl();
            if (focus != null && !Focus.urlMatches(base, focus)) {
                hidden++;
                continue;
            }
            if (urlFilter != null && (base == null || !base.toLowerCase().contains(urlFilter.toLowerCase()))) {
                continue;
            }
            if (issue.severity() != null) {
                severityCounts.merge(issue.severity().name(), 1, Integer::sum);
            }
            if (severityFilter != null && (issue.severity() == null
                    || !issue.severity().name().equalsIgnoreCase(severityFilter))) {
                continue;
            }
            out.add(Tools.summarizeIssue(i, issue));
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("total", out.size());
        data.put("severity_counts", severityCounts);
        data.put("returned", out.size());
        data.put("issues", out);
        if (focus != null) {
            data.put("task_focus_host", focus);
            data.put("hidden_other_hosts", hidden);
        }
        return ToolResult.ok(data);
    }

    private static ToolResult inspectIssue(Map<String, Object> args, ToolContext ctx) {
        Integer id = Tools.intOrNull(args, "issue_id");
        if (id == null) {
            return ToolResult.error("issue_id is required.");
        }
        List<AuditIssue> issues = ctx.api.siteMap().issues();
        if (id < 0 || id >= issues.size()) {
            return ToolResult.error("issue_id " + id + " out of range (0.." + (issues.size() - 1) + ").");
        }
        return ToolResult.ok(Tools.detailIssue(id, issues.get(id), DETAIL_MAX));
    }

    private static ToolResult listDefinitions(Map<String, Object> args, ToolContext ctx) {
        Set<String> names = new LinkedHashSet<>();
        for (AuditIssue issue : ctx.api.siteMap().issues()) {
            try {
                names.add(issue.definition().name());
            } catch (RuntimeException ignored) {
                names.add(issue.name());
            }
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("definitions", names);
        data.put("note", "Only definitions present in current issues are listed; Montoya does not expose the full built-in catalog.");
        return ToolResult.ok(data);
    }

    private static ToolResult createIssue(Map<String, Object> args, ToolContext ctx) {
        String name = Tools.str(args, "name");
        String baseUrl = Tools.str(args, "base_url");
        if (name == null || baseUrl == null) {
            return ToolResult.error("name and base_url are required.");
        }
        AuditIssueSeverity severity = parseSeverity(Tools.str(args, "severity", "INFORMATION"));
        AuditIssueConfidence confidence = parseConfidence(Tools.str(args, "confidence", "TENTATIVE"));
        String detail = Tools.str(args, "detail", "");
        String remediation = Tools.str(args, "remediation", "");

        List<HttpRequestResponse> evidence = new ArrayList<>();
        Integer requestId = Tools.intOrNull(args, "request_id");
        if (requestId != null) {
            MessageStore.Entry entry = ctx.messages.get(requestId);
            if (entry != null) {
                evidence.add(entry.message);
            }
        }

        try {
            AuditIssue issue = AuditIssue.auditIssue(
                    name, detail, remediation, baseUrl, severity, confidence,
                    null, null, severity, evidence);
            ctx.api.siteMap().add(issue);
        } catch (RuntimeException e) {
            return ToolResult.error("Failed to create issue: " + e.getMessage());
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("created", true);
        data.put("name", name);
        data.put("base_url", baseUrl);
        data.put("severity", severity.name());
        return ToolResult.ok(data);
    }

    private static AuditIssueSeverity parseSeverity(String s) {
        try {
            return AuditIssueSeverity.valueOf(s.trim().toUpperCase());
        } catch (RuntimeException e) {
            return AuditIssueSeverity.INFORMATION;
        }
    }

    private static AuditIssueConfidence parseConfidence(String s) {
        try {
            return AuditIssueConfidence.valueOf(s.trim().toUpperCase());
        } catch (RuntimeException e) {
            return AuditIssueConfidence.TENTATIVE;
        }
    }
}
