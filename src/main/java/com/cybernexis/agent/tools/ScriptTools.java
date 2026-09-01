/*
 * Script tools. run_custom_script compiles and runs a Montoya script body at
 * runtime (requires a JDK). Scripts can be stored/updated and their last result
 * inspected. run_skill_script (PortSwigger skill packages) is not available here.
 */
package com.cybernexis.agent.tools;

import java.util.LinkedHashMap;
import java.util.Map;

import com.cybernexis.agent.script.RuntimeJavaCompiler;

public final class ScriptTools {

    private ScriptTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "run_custom_script",
                "Compile and run a Java Montoya script. Provide the METHOD BODY only (statements ending in a return); `api` (MontoyaApi) is in scope. Common Montoya packages are auto-imported. Requires Burp on a JDK. "
                        + "CHEAT-SHEET (use these exact signatures): build a request with HttpRequest.httpRequestFromUrl(\"https://host/path\"); "
                        + "add/replace headers via request.withAddedHeader(name,value) / request.withHeader(name,value); change path via request.withPath(\"/x\"); "
                        + "set body via request.withBody(\"...\"); send it with HttpRequestResponse rr = api.http().sendRequest(request); "
                        + "read the response via rr.response().statusCode() and rr.response().bodyToString(). "
                        + "Existing traffic is api.siteMap().requestResponses() (note the capital M) and api.proxy().history(). "
                        + "There is NO api.http().buildHttpRequest(...) and NO api.sitemap(); do not guess method names — call query_montoya_api instead. args: source (required), name?.",
                true,
                Schema.object()
                        .prop("source", "string", "Java statements ending in 'return <value>;'.")
                        .prop("name", "string", "Optional name to also store the script under.")
                        .require("source")
                        .build(),
                ScriptTools::runCustomScript));

        registry.register(new ToolDescriptor(
                "update_script",
                "Store or replace a named script's source (does not run it). args: name (required), source (required).",
                true,
                Schema.object()
                        .prop("name", "string", "Script name.")
                        .prop("source", "string", "Script body.")
                        .require("name", "source")
                        .build(),
                ScriptTools::updateScript));

        registry.register(new ToolDescriptor(
                "inspect_script_result",
                "Return the value produced by the most recent run_custom_script call.",
                false,
                ToolDescriptor.emptyParams(),
                ScriptTools::inspectScriptResult));

        registry.register(new ToolDescriptor(
                "run_skill_script",
                "Run a PortSwigger skill package. Not supported — use run_custom_script instead.",
                true,
                Schema.object().prop("skill", "string", "Skill name.").build(),
                (a, c) -> ToolResult.error("run_skill_script requires PortSwigger skill packages and is not supported here. Use run_custom_script instead.")));
    }

    private static ToolResult runCustomScript(Map<String, Object> args, ToolContext ctx) {
        String source = Tools.str(args, "source");
        if (source == null || source.isEmpty()) {
            return ToolResult.error("source is required.");
        }
        String name = Tools.str(args, "name");
        if (name != null) {
            ctx.putScript(name, source);
        }
        Object result;
        try {
            result = RuntimeJavaCompiler.compileAndRun(source, ctx.api);
        } catch (RuntimeJavaCompiler.ScriptCompilationException ce) {
            return ToolResult.error("Compilation failed:\n" + ce.getMessage());
        } catch (IllegalStateException ise) {
            return ToolResult.error(ise.getMessage());
        } catch (Exception e) {
            return ToolResult.error("Script threw: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        ctx.setLastScriptResult(result);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("result", result == null ? null : Tools.truncate(String.valueOf(result), 6000));
        data.put("result_type", result == null ? "null" : result.getClass().getSimpleName());
        return ToolResult.ok(data);
    }

    private static ToolResult updateScript(Map<String, Object> args, ToolContext ctx) {
        String name = Tools.str(args, "name");
        String source = Tools.str(args, "source");
        if (name == null || source == null) {
            return ToolResult.error("name and source are required.");
        }
        ctx.putScript(name, source);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("stored", name);
        data.put("length", source.length());
        return ToolResult.ok(data);
    }

    private static ToolResult inspectScriptResult(Map<String, Object> args, ToolContext ctx) {
        Object result = ctx.getLastScriptResult();
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("has_result", result != null);
        data.put("result", result == null ? null : Tools.truncate(String.valueOf(result), 6000));
        return ToolResult.ok(data);
    }
}
