/*
 * A parsed single-turn model response: either a tool call (tool != null) or a
 * final answer (answer != null).
 */
package com.cybernexis.agent.loop;

import java.util.LinkedHashMap;
import java.util.Map;

public class ToolCall {

    public String thought = "";
    public String tool;
    public Map<String, Object> args = new LinkedHashMap<>();
    public String answer;
    /** How the response was parsed: "native", "json", or "regex". */
    public String parseLevel = "json";

    public boolean isFinal() {
        return tool == null || tool.isEmpty();
    }
}
