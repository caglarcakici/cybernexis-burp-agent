/*
 * A single tool the agent can call: metadata for the prompt/native schema plus
 * the executor that runs it against Burp.
 */
package com.cybernexis.agent.tools;

import java.util.LinkedHashMap;
import java.util.Map;

public class ToolDescriptor {

    public interface Executor {
        ToolResult execute(Map<String, Object> args, ToolContext ctx);
    }

    public final String name;
    public final String description;
    /** True if the tool mutates Burp state or sends traffic (requires confirmation). */
    public final boolean action;
    /** JSON-schema "parameters" object for the OpenAI-compatible tools array. */
    public final Map<String, Object> parameters;
    public final Executor executor;

    public ToolDescriptor(String name, String description, boolean action,
                          Map<String, Object> parameters, Executor executor) {
        this.name = name;
        this.description = description;
        this.action = action;
        this.parameters = parameters == null ? emptyParams() : parameters;
        this.executor = executor;
    }

    public Map<String, Object> toOpenAiTool() {
        Map<String, Object> fn = new LinkedHashMap<>();
        fn.put("name", name);
        fn.put("description", description);
        fn.put("parameters", parameters);
        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("type", "function");
        tool.put("function", fn);
        return tool;
    }

    public static Map<String, Object> emptyParams() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("type", "object");
        p.put("properties", new LinkedHashMap<String, Object>());
        return p;
    }
}
