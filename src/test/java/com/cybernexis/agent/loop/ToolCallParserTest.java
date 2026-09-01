/*
 * Parser tests covering the three levels: clean JSON, fenced JSON, and dirty
 * output that needs regex salvage.
 */
package com.cybernexis.agent.loop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;

class ToolCallParserTest {

    @Test
    void parsesCleanToolCall() {
        ToolCall call = ToolCallParser.parse(
                "{\"thought\":\"list scope\",\"tool\":\"inspect_scope\",\"args\":{}}", new ArrayList<>());
        assertEquals("inspect_scope", call.tool);
        assertEquals("json", call.parseLevel);
        assertTrue(call.args.isEmpty());
    }

    @Test
    void parsesFencedJson() {
        ToolCall call = ToolCallParser.parse(
                "```json\n{\"thought\":\"go\",\"tool\":\"send_to\",\"args\":{\"destination\":\"repeater\"}}\n```",
                new ArrayList<>());
        assertEquals("send_to", call.tool);
        assertEquals("repeater", call.args.get("destination"));
    }

    @Test
    void parsesFinalAnswer() {
        ToolCall call = ToolCallParser.parse(
                "{\"thought\":\"done\",\"tool\":null,\"args\":null,\"answer\":\"# Plan\\nHello\"}",
                new ArrayList<>());
        assertNull(call.tool);
        assertTrue(call.isFinal());
        assertTrue(call.answer.contains("Plan"));
    }

    @Test
    void salvagesDirtyOutputWithRegex() {
        ToolCall call = ToolCallParser.parse(
                "Sure! Here you go: \"tool\": \"list_issues\", \"args\": {\"severity\":\"HIGH\"} hope that helps",
                new ArrayList<>());
        assertEquals("list_issues", call.tool);
        assertEquals("regex", call.parseLevel);
    }

    @Test
    void recoversTruncatedFinalAnswer() {
        // Simulates the model hitting the token limit mid-answer: no closing quote/brace.
        String truncated = "{\"thought\":\"summary\",\"tool\":null,\"args\":null,"
                + "\"answer\":\"# Overview\\n\\n## Domains\\n- a.example.com\\n- b.exam";
        ToolCall call = ToolCallParser.parse(truncated, new ArrayList<>());
        assertNull(call.tool);
        assertTrue(call.isFinal());
        assertTrue(call.answer.startsWith("# Overview"));
        assertTrue(call.answer.contains("\n"), "escaped newlines should be unescaped");
        assertTrue(call.answer.contains("a.example.com"));
    }
}
