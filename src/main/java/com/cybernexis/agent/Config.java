/*
 * User-configurable settings for Cybernexis Agent. Plain POJO (no Burp
 * dependency) so it is unit-testable; persistence is handled by ConfigStore.
 */
package com.cybernexis.agent;

import java.util.LinkedHashMap;
import java.util.Map;

import com.cybernexis.agent.json.Json;

public class Config {

    public String baseUrl = "http://127.0.0.1:11434";
    public String model = "orcarouter/Qwen3.8-27B-Uncensored:latest";
    public double temperature = 0.1;
    public int maxTokens = 4096;
    public int maxSteps = 8;
    public int timeoutSeconds = 120;
    public boolean confirmActions = true;

    /** Approximate character budget for the conversation sent to the model each turn. */
    public int contextCharBudget = 24000;

    /** When true, action tools targeting out-of-scope hosts are blocked. */
    public boolean enforceScope = true;

    /**
     * Default approval mode for new chat sessions:
     * "manual" = ask before every action tool,
     * "smart"  = auto-approve most actions, escalate high-impact ones to a prompt,
     * "auto"   = never ask.
     */
    public String agentMode = "smart";

    /** When true, use OpenAI-compatible /v1/chat/completions; otherwise native /api/chat. */
    public boolean useOpenAiEndpoint = false;

    /**
     * When true, the registered Burp passive scan check sends in-scope HTTP
     * exchanges to the local model and reports findings as native issues.
     * Default false — the check is registered but returns immediately until enabled.
     */
    public boolean passiveAiScan = false;

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("base_url", baseUrl);
        m.put("model", model);
        m.put("temperature", temperature);
        m.put("max_tokens", maxTokens);
        m.put("max_steps", maxSteps);
        m.put("timeout_seconds", timeoutSeconds);
        m.put("confirm_actions", confirmActions);
        m.put("context_char_budget", contextCharBudget);
        m.put("enforce_scope", enforceScope);
        m.put("agent_mode", agentMode);
        m.put("use_openai_endpoint", useOpenAiEndpoint);
        m.put("passive_ai_scan", passiveAiScan);
        return m;
    }

    public String toJson() {
        return Json.writePretty(toMap());
    }

    public static Config fromJson(String json) {
        Config c = new Config();
        if (json == null || json.trim().isEmpty()) {
            return c;
        }
        Map<String, Object> m = Json.parseObject(json);
        c.baseUrl = Json.asString(m.getOrDefault("base_url", c.baseUrl), c.baseUrl);
        c.model = Json.asString(m.getOrDefault("model", c.model), c.model);
        Object t = m.get("temperature");
        if (t instanceof Number) {
            c.temperature = ((Number) t).doubleValue();
        }
        c.maxTokens = Json.asInt(m.getOrDefault("max_tokens", c.maxTokens), c.maxTokens);
        c.maxSteps = Json.asInt(m.getOrDefault("max_steps", c.maxSteps), c.maxSteps);
        c.timeoutSeconds = Json.asInt(m.getOrDefault("timeout_seconds", c.timeoutSeconds), c.timeoutSeconds);
        c.confirmActions = Json.asBool(m.getOrDefault("confirm_actions", c.confirmActions), c.confirmActions);
        c.contextCharBudget = Json.asInt(m.getOrDefault("context_char_budget", c.contextCharBudget), c.contextCharBudget);
        c.enforceScope = Json.asBool(m.getOrDefault("enforce_scope", c.enforceScope), c.enforceScope);
        c.agentMode = Json.asString(m.getOrDefault("agent_mode", c.agentMode), c.agentMode);
        c.useOpenAiEndpoint = Json.asBool(m.getOrDefault("use_openai_endpoint", c.useOpenAiEndpoint), c.useOpenAiEndpoint);
        c.passiveAiScan = Json.asBool(m.getOrDefault("passive_ai_scan", c.passiveAiScan), c.passiveAiScan);
        return c;
    }

    public String normalizedBaseUrl() {
        String u = baseUrl == null ? "" : baseUrl.trim();
        while (u.endsWith("/")) {
            u = u.substring(0, u.length() - 1);
        }
        return u;
    }
}
