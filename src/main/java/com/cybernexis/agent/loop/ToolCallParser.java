/*
 * Three-level tolerant parser for the model's per-turn response:
 *   L1 native  - OpenAI-style tool_calls returned by /v1
 *   L2 json    - a single JSON object matching the response contract
 *   L3 regex   - best-effort extraction when the model wraps or dirties the JSON
 */
package com.cybernexis.agent.loop;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.cybernexis.agent.json.Json;
import com.cybernexis.agent.ollama.OllamaClient;

public final class ToolCallParser {

    private static final Pattern TOOL_PATTERN =
            Pattern.compile("\"tool\"\\s*:\\s*\"([a-zA-Z_][a-zA-Z0-9_]*)\"");
    private static final Pattern ANSWER_PATTERN =
            Pattern.compile("\"answer\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"", Pattern.DOTALL);

    private ToolCallParser() {
    }

    public static ToolCall parse(String content, List<OllamaClient.ToolCallRaw> nativeCalls) {
        // Level 1: native tool calls
        if (nativeCalls != null && !nativeCalls.isEmpty()) {
            OllamaClient.ToolCallRaw raw = nativeCalls.get(0);
            ToolCall call = new ToolCall();
            call.parseLevel = "native";
            call.tool = raw.name;
            call.args = Json.parseObject(raw.arguments);
            call.thought = firstThought(content);
            return call;
        }

        String cleaned = stripFences(content);

        // Level 2: strict JSON object matching the response contract
        String jsonObject = extractContractObject(cleaned);
        if (jsonObject != null) {
            Object parsed = Json.parse(jsonObject);
            if (parsed instanceof Map) {
                ToolCall call = fromMap((Map<?, ?>) parsed);
                call.parseLevel = "json";
                return call;
            }
        }

        // Level 3: regex salvage (also handles truncated / unterminated JSON)
        ToolCall call = new ToolCall();
        call.parseLevel = "regex";
        call.thought = firstThought(cleaned);
        Matcher toolMatcher = TOOL_PATTERN.matcher(cleaned);
        if (toolMatcher.find() && !"null".equals(toolMatcher.group(1))) {
            call.tool = toolMatcher.group(1);
            String argsBlock = extractArgsBlock(cleaned);
            if (argsBlock != null) {
                call.args = Json.parseObject(argsBlock);
            }
            return call;
        }
        String answer = extractAnswer(cleaned);
        if (answer != null) {
            call.answer = answer;
        } else {
            Matcher answerMatcher = ANSWER_PATTERN.matcher(cleaned);
            if (answerMatcher.find()) {
                call.answer = unescape(answerMatcher.group(1));
            } else {
                // No structure at all: treat the whole thing as the final answer.
                call.answer = cleaned.trim();
            }
        }
        return call;
    }

    private static ToolCall fromMap(Map<?, ?> map) {
        ToolCall call = new ToolCall();
        Object thought = map.get("thought");
        if (thought != null) {
            call.thought = String.valueOf(thought);
        }
        Object tool = map.get("tool");
        if (tool != null && !"null".equals(String.valueOf(tool)) && !String.valueOf(tool).isEmpty()) {
            call.tool = String.valueOf(tool);
        }
        Object args = map.get("args");
        if (args instanceof Map) {
            call.args = Json.asMap(args);
        }
        Object answer = map.get("answer");
        if (answer != null && !"null".equals(String.valueOf(answer))) {
            call.answer = String.valueOf(answer);
        }
        return call;
    }

    private static String stripFences(String s) {
        if (s == null) {
            return "";
        }
        String t = s.trim();
        if (t.startsWith("```")) {
            int firstNl = t.indexOf('\n');
            if (firstNl >= 0) {
                t = t.substring(firstNl + 1);
            }
            int lastFence = t.lastIndexOf("```");
            if (lastFence >= 0) {
                t = t.substring(0, lastFence);
            }
        }
        return t.trim();
    }

    /** Extract the first balanced {...} block, respecting strings and escapes. */
    static String extractJsonObject(String s) {
        return extractJsonObjectFrom(s, s.indexOf('{'));
    }

    /**
     * Find the first balanced {...} block that actually looks like the response
     * contract (contains a top-level thought/tool/answer key), skipping unrelated
     * objects such as a bare args map embedded in prose.
     */
    static String extractContractObject(String s) {
        int from = 0;
        while (true) {
            int start = s.indexOf('{', from);
            if (start < 0) {
                return null;
            }
            String block = extractJsonObjectFrom(s, start);
            if (block == null) {
                return null;
            }
            Object parsed = Json.parse(block);
            if (parsed instanceof Map) {
                Map<?, ?> map = (Map<?, ?>) parsed;
                if (map.containsKey("thought") || map.containsKey("tool") || map.containsKey("answer")) {
                    return block;
                }
            }
            from = start + 1;
        }
    }

    private static String extractJsonObjectFrom(String s, int start) {
        if (start < 0) {
            return null;
        }
        int depth = 0;
        boolean inString = false;
        boolean escape = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inString) {
                if (escape) {
                    escape = false;
                } else if (c == '\\') {
                    escape = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return s.substring(start, i + 1);
                }
            }
        }
        return null;
    }

    private static String extractArgsBlock(String s) {
        int idx = s.indexOf("\"args\"");
        if (idx < 0) {
            return null;
        }
        int brace = s.indexOf('{', idx);
        if (brace < 0) {
            return null;
        }
        return extractJsonObjectFrom(s, brace);
    }

    /**
     * Extract the value of "answer" even when the JSON is truncated (no closing
     * quote or brace, e.g. the model hit the token limit mid-string). Returns the
     * fully unescaped markdown, or null if there is no answer field.
     */
    static String extractAnswer(String s) {
        int key = s.indexOf("\"answer\"");
        if (key < 0) {
            return null;
        }
        int colon = s.indexOf(':', key + "\"answer\"".length());
        if (colon < 0) {
            return null;
        }
        int open = s.indexOf('"', colon + 1);
        if (open < 0) {
            return null;
        }
        StringBuilder raw = new StringBuilder();
        boolean escape = false;
        for (int i = open + 1; i < s.length(); i++) {
            char c = s.charAt(i);
            if (escape) {
                raw.append(c);
                escape = false;
                continue;
            }
            if (c == '\\') {
                raw.append(c);
                escape = true;
                continue;
            }
            if (c == '"') {
                break; // closing quote of the answer string
            }
            raw.append(c);
        }
        String captured = raw.toString();
        if (captured.endsWith("\\")) {
            // dangling escape from truncation; drop it so re-parsing succeeds
            captured = captured.substring(0, captured.length() - 1);
        }
        Object parsed = Json.parse("\"" + captured + "\"");
        return parsed instanceof String ? (String) parsed : captured;
    }

    private static String firstThought(String s) {
        if (s == null) {
            return "";
        }
        Matcher m = Pattern.compile("\"thought\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"").matcher(s);
        if (m.find()) {
            return unescape(m.group(1));
        }
        return "";
    }

    private static String unescape(String s) {
        return s.replace("\\n", "\n").replace("\\t", "\t").replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
