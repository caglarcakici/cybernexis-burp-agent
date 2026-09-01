/*
 * The agent loop: builds the prompt, streams a turn from Ollama, parses the
 * response, executes the chosen tool against Burp, feeds the result back, and
 * repeats until a final answer or the step limit is reached.
 */
package com.cybernexis.agent.loop;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.cybernexis.agent.Config;
import com.cybernexis.agent.json.Json;
import com.cybernexis.agent.ollama.OllamaClient;
import com.cybernexis.agent.tools.ToolContext;
import com.cybernexis.agent.tools.ToolDescriptor;
import com.cybernexis.agent.tools.ToolRegistry;
import com.cybernexis.agent.tools.ToolResult;

public class AgentLoop {

    public interface Listener {
        void onStatus(String status);

        void onModelToken(String token);

        void onTurnParsed(int step, ToolCall call);

        void onToolResult(String tool, ToolResult result);

        void onFinalAnswer(String markdown);

        void onError(String message);

        void onLogEvent(Map<String, Object> event);

        /** Return true to allow an action tool to run. Called on a background thread. */
        boolean confirmAction(ToolDescriptor descriptor, Map<String, Object> args);
    }

    private final Config config;
    private final OllamaClient client;
    private final ToolRegistry registry;
    private final ToolContext toolContext;
    private final PromptBuilder promptBuilder;

    private final List<Map<String, Object>> conversation = new ArrayList<>();
    private final com.cybernexis.agent.tools.VarStore vars = new com.cybernexis.agent.tools.VarStore();
    private String systemAddendum;
    private String focusHost;

    public AgentLoop(Config config, OllamaClient client, ToolRegistry registry, ToolContext toolContext) {
        this.config = config;
        this.client = client;
        this.registry = registry;
        this.toolContext = toolContext;
        this.promptBuilder = new PromptBuilder(registry);
    }

    /** Clears the running conversation history. */
    public void reset() {
        conversation.clear();
    }

    /** Extra task-specific instructions appended to the system prompt (from a template). */
    public void setSystemAddendum(String addendum) {
        this.systemAddendum = addendum;
    }

    public String getSystemAddendum() {
        return systemAddendum;
    }

    public void setFocusHost(String host) {
        this.focusHost = com.cybernexis.agent.tools.Focus.normalize(host);
    }

    public String getFocusHost() {
        return focusHost;
    }

    public java.util.Map<String, String> snapshotVariables() {
        return vars.snapshot();
    }

    public void restoreVariables(java.util.Map<String, String> incoming) {
        vars.restore(incoming);
    }

    /** Full history for persistence. */
    public List<Map<String, Object>> snapshotConversation() {
        return new ArrayList<>(conversation);
    }

    public void restoreConversation(List<Map<String, Object>> messages) {
        conversation.clear();
        if (messages != null) {
            conversation.addAll(messages);
        }
    }

    public void runUserTurn(String userMessage, Listener listener, OllamaClient.CancelToken cancel) {
        conversation.add(message("user", userMessage));
        String inferred = com.cybernexis.agent.tools.Focus.inferHost(userMessage);
        if (inferred != null) {
            focusHost = inferred;
        }
        toolContext.beginTurn(focusHost, vars);
        try {
            runSteps(listener, cancel);
        } finally {
            toolContext.endTurn();
        }
    }

    private void runSteps(Listener listener, OllamaClient.CancelToken cancel) {
        List<Map<String, Object>> tools = config.useOpenAiEndpoint ? openAiTools() : null;

        for (int step = 1; step <= config.maxSteps; step++) {
            if (cancel.isCancelled()) {
                listener.onStatus("Stopped.");
                return;
            }
            listener.onStatus("Thinking (step " + step + "/" + config.maxSteps + ")...");

            toolContext.messages.refresh(toolContext.api);
            String system = promptBuilder.buildSystemMessage(toolContext, config.maxSteps);
            if (systemAddendum != null && !systemAddendum.trim().isEmpty()) {
                system = system + "\nTASK INSTRUCTIONS (follow these for this session)\n"
                        + systemAddendum.trim() + "\n";
            }

            List<Map<String, Object>> outgoing = new ArrayList<>();
            outgoing.add(message("system", system));
            outgoing.addAll(buildOutgoingHistory(config.contextCharBudget));

            OllamaClient.ChatResult result;
            try {
                result = client.streamChat(outgoing, tools, listener::onModelToken, cancel);
            } catch (Exception e) {
                if (cancel.isCancelled()) {
                    listener.onStatus("Stopped.");
                    return;
                }
                listener.onError("Ollama request failed: " + e.getMessage());
                return;
            }

            if (result.timedOut && (result.content == null || result.content.trim().isEmpty())) {
                listener.onError("Ollama stopped responding: no tokens for " + config.timeoutSeconds
                        + "s (idle timeout). The server may be overloaded, still loading the model,"
                        + " or unreachable. Check the Ollama logs, or raise timeout_seconds in settings.");
                return;
            }

            ToolCall call = ToolCallParser.parse(result.content, result.toolCalls);
            conversation.add(message("assistant", assistantEcho(call, result.content)));
            listener.onTurnParsed(step, call);
            logEvent(listener, step, call);

            if (call.isFinal() || result.timedOut) {
                String answer = call.answer != null && !call.answer.isEmpty() ? call.answer : call.thought;
                if ((answer == null || answer.isEmpty()) && result.content != null) {
                    // Truncated mid tool-call: fall back to the raw partial text.
                    answer = result.content.trim();
                }
                answer = (answer == null || answer.isEmpty()) ? "(no answer)" : answer;
                if (result.timedOut) {
                    answer += "\n\n---\n_⚠️ Yanıt, model " + config.timeoutSeconds
                            + " sn boyunca yeni token üretmediği için erken kesildi ve kısmi olarak kurtarıldı."
                            + " Tamamlamak için tekrar sorun veya settings'ten timeout_seconds değerini artırın._";
                }
                listener.onFinalAnswer(answer);
                return;
            }

            ToolDescriptor descriptor = registry.get(call.tool);
            if (descriptor == null) {
                String suggestion = registry.suggest(call.tool);
                String err = "Unknown tool '" + call.tool + "'."
                        + (suggestion != null ? " Did you mean '" + suggestion + "'?" : "")
                        + " Use only the exact names from the catalog.";
                ToolResult tr = ToolResult.error(err);
                listener.onToolResult(call.tool, tr);
                conversation.add(message("user", toolResultMessage(call.tool, tr)));
                continue;
            }

            if (descriptor.action && config.enforceScope) {
                String block = ScopeGuard.check(descriptor.name, call.args, toolContext.api);
                if (block != null) {
                    ToolResult tr = ToolResult.error(block);
                    listener.onToolResult(descriptor.name, tr);
                    conversation.add(message("user", toolResultMessage(descriptor.name, tr)));
                    continue;
                }
            }

            if (descriptor.action) {
                listener.onStatus("Waiting for confirmation of action: " + descriptor.name);
                boolean allowed = listener.confirmAction(descriptor, call.args);
                if (!allowed) {
                    ToolResult tr = ToolResult.error("User declined to run action tool '" + descriptor.name + "'.");
                    listener.onToolResult(descriptor.name, tr);
                    conversation.add(message("user", toolResultMessage(descriptor.name, tr)));
                    continue;
                }
            }

            if (cancel.isCancelled()) {
                listener.onStatus("Stopped.");
                return;
            }

            listener.onStatus("Running tool: " + descriptor.name);
            ToolResult toolResult;
            try {
                toolResult = descriptor.executor.execute(call.args, toolContext);
            } catch (Exception e) {
                toolResult = ToolResult.error(descriptor.name + " threw: " + e.getClass().getSimpleName()
                        + ": " + e.getMessage());
            }
            listener.onToolResult(descriptor.name, toolResult);
            logToolResult(listener, step, descriptor.name, call.args, toolResult);
            conversation.add(message("user", toolResultMessage(descriptor.name, toolResult)));
        }

        listener.onStatus("Reached max steps (" + config.maxSteps + ").");
        listener.onFinalAnswer("_Reached the maximum of " + config.maxSteps
                + " tool calls without a final answer. Ask a narrower question or raise max_steps in settings._");
    }

    private List<Map<String, Object>> openAiTools() {
        List<Map<String, Object>> tools = new ArrayList<>();
        for (ToolDescriptor d : registry.all()) {
            tools.add(d.toOpenAiTool());
        }
        return tools;
    }

    /**
     * Builds the history to send this turn within a rough character budget:
     * caps each message, always keeps the first user task, and keeps as many of
     * the most recent messages as fit — inserting a marker if the middle is
     * dropped. The stored {@code conversation} (used for persistence) is untouched.
     */
    private List<Map<String, Object>> buildOutgoingHistory(int budget) {
        int perMsgCap = 4000;
        List<Map<String, Object>> capped = new ArrayList<>();
        for (Map<String, Object> m : conversation) {
            String role = String.valueOf(m.get("role"));
            String content = String.valueOf(m.get("content"));
            if (content.length() > perMsgCap) {
                content = content.substring(0, perMsgCap)
                        + "\n...[truncated " + (content.length() - perMsgCap) + " chars]";
            }
            capped.add(message(role, content));
        }
        if (capped.size() <= 2) {
            return capped;
        }
        int safeBudget = Math.max(4000, budget);
        Map<String, Object> first = capped.get(0);
        int used = len(first);
        java.util.Deque<Map<String, Object>> recent = new java.util.ArrayDeque<>();
        for (int i = capped.size() - 1; i >= 1; i--) {
            int l = len(capped.get(i));
            if (used + l > safeBudget && !recent.isEmpty()) {
                break;
            }
            used += l;
            recent.addFirst(capped.get(i));
        }
        List<Map<String, Object>> result = new ArrayList<>();
        result.add(first);
        if (recent.size() < capped.size() - 1) {
            result.add(message("user",
                    "[Earlier steps were trimmed to save context. Re-run a tool if you need its details again.]"));
        }
        result.addAll(recent);
        return result;
    }

    private static int len(Map<String, Object> m) {
        Object c = m.get("content");
        return (c == null ? 0 : String.valueOf(c).length()) + 24;
    }

    private static Map<String, Object> message(String role, String content) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("role", role);
        m.put("content", content);
        return m;
    }

    private static String assistantEcho(ToolCall call, String raw) {
        // Keep a compact, contract-shaped echo so history stays clean regardless of parse level.
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("thought", call.thought);
        if (call.isFinal()) {
            m.put("tool", null);
            m.put("args", null);
            m.put("answer", call.answer);
        } else {
            m.put("tool", call.tool);
            m.put("args", call.args);
        }
        return Json.write(m);
    }

    private static String toolResultMessage(String tool, ToolResult result) {
        return "TOOL RESULT (" + tool + "): " + result.toJson();
    }

    private void logEvent(Listener listener, int step, ToolCall call) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("step", step);
        event.put("parse_level", call.parseLevel);
        event.put("thought", call.thought);
        event.put("tool", call.tool);
        event.put("args", call.args);
        if (call.isFinal()) {
            event.put("final", true);
        }
        listener.onLogEvent(event);
    }

    private void logToolResult(Listener listener, int step, String tool,
                               Map<String, Object> args, ToolResult result) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("step", step);
        event.put("tool_executed", tool);
        event.put("args", args);
        event.put("result", result.toMap());
        listener.onLogEvent(event);
    }
}
