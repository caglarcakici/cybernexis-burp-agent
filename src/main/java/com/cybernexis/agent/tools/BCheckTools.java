/*
 * Custom scan checks via Burp's BChecks engine. The model writes a BCheck script
 * which Burp compiles and enables; imported checks are tracked for listing.
 * Deletion is not exposed by the Montoya API.
 */
package com.cybernexis.agent.tools;

import java.util.LinkedHashMap;
import java.util.Map;

import burp.api.montoya.scanner.bchecks.BCheckImportResult;

public final class BCheckTools {

    private BCheckTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "list_custom_scan_checks",
                "List custom BCheck scan checks imported during this session (id, status, snippet).",
                false,
                ToolDescriptor.emptyParams(),
                BCheckTools::listChecks));

        registry.register(new ToolDescriptor(
                "create_custom_scan_check",
                "Import a custom scan check written in Burp's BCheck language. If it fails to compile, the errors are returned and nothing changes. args: script (required), name?.",
                true,
                Schema.object()
                        .prop("script", "string", "BCheck source (metadata: ... given ... then ...).")
                        .prop("name", "string", "Optional label for tracking.")
                        .require("script")
                        .build(),
                BCheckTools::createCheck));

        registry.register(new ToolDescriptor(
                "edit_custom_scan_check",
                "Re-import an updated BCheck (the Montoya API has no in-place edit, so this imports a new version). args: script (required), name?.",
                true,
                Schema.object()
                        .prop("script", "string", "Updated BCheck source.")
                        .prop("name", "string", "Optional label.")
                        .require("script")
                        .build(),
                BCheckTools::createCheck));

        registry.register(new ToolDescriptor(
                "delete_custom_scan_check",
                "Delete a custom scan check. Not supported by the Montoya API (remove it in the Burp UI).",
                true,
                Schema.object().prop("check_id", "string", "Check id.").build(),
                (a, c) -> ToolResult.error("delete_custom_scan_check is not supported by the Montoya API.")));
    }

    private static ToolResult listChecks(Map<String, Object> args, ToolContext ctx) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("checks", ctx.importedChecks());
        data.put("note", "Only checks imported via this extension in the current session are listed.");
        return ToolResult.ok(data);
    }

    private static ToolResult createCheck(Map<String, Object> args, ToolContext ctx) {
        String script = Tools.str(args, "script");
        if (script == null || script.isEmpty()) {
            return ToolResult.error("script is required.");
        }
        BCheckImportResult result;
        try {
            result = ctx.api.scanner().bChecks().importBCheck(script);
        } catch (RuntimeException e) {
            return ToolResult.error("BCheck import failed: " + e.getMessage());
        }
        boolean ok = result.status() == BCheckImportResult.Status.LOADED_WITHOUT_ERRORS;
        if (!ok) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("status", result.status().name());
            err.put("import_errors", result.importErrors());
            return ToolResult.error("BCheck loaded with errors: " + String.join("; ", result.importErrors()));
        }
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", Tools.str(args, "name", "(unnamed)"));
        info.put("status", result.status().name());
        info.put("snippet", Tools.truncate(script, 200));
        String id = ctx.registerImportedCheck(info);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("check_id", id);
        data.put("status", result.status().name());
        data.put("enabled", true);
        return ToolResult.ok(data);
    }
}
