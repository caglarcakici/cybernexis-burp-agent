/*
 * Result of executing a single tool. Serializes to the JSON that is fed back to
 * the model as a tool_result on the next turn.
 */
package com.cybernexis.agent.tools;

import java.util.LinkedHashMap;
import java.util.Map;

import com.cybernexis.agent.json.Json;

public class ToolResult {

    public final boolean ok;
    public final Object data;
    public final String error;

    private ToolResult(boolean ok, Object data, String error) {
        this.ok = ok;
        this.data = data;
        this.error = error;
    }

    public static ToolResult ok(Object data) {
        return new ToolResult(true, data, null);
    }

    public static ToolResult error(String message) {
        return new ToolResult(false, null, message);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        if (ok) {
            m.put("data", data);
        } else {
            m.put("error", error);
        }
        return m;
    }

    public String toJson() {
        return Json.write(toMap());
    }
}
