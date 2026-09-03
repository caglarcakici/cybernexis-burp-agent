/*
 * User-configurable settings for Cybernexis Agent. Plain POJO (no Burp
 * dependency) so it is unit-testable; persistence is handled by ConfigStore.
 */
package com.cybernexis.agent;

import java.util.LinkedHashMap;
import java.util.Map;

import com.cybernexis.agent.json.Json;

public class Config {

    public static final String PROVIDER_OLLAMA = "ollama";
    public static final String PROVIDER_OPENAI = "openai";
    public static final String PROVIDER_ANTHROPIC = "anthropic";

    /** Wire protocol/provider used for model requests. */
    public String provider = PROVIDER_OLLAMA;
    public String baseUrl = "http://127.0.0.1:11434";
    /** Relative path or absolute URL for chat generation. */
    public String chatEndpoint = "/api/chat";
    /** Relative path or absolute URL for model discovery. */
    public String modelsEndpoint = "/api/tags";
    public String model = "orcarouter/Qwen3.8-27B-Uncensored:latest";
    /** Optional provider credential. Stored in Burp's extension preferences. */
    public String apiToken = "";
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

    /**
     * When true, the registered Burp passive scan check sends in-scope HTTP
     * exchanges to the selected model and reports findings as native issues.
     * Default false — the check is registered but returns immediately until enabled.
     */
    public boolean passiveAiScan = false;

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("provider", normalizedProvider());
        m.put("base_url", baseUrl);
        m.put("chat_endpoint", chatEndpoint);
        m.put("models_endpoint", modelsEndpoint);
        m.put("model", model);
        m.put("api_token", apiToken);
        m.put("temperature", temperature);
        m.put("max_tokens", maxTokens);
        m.put("max_steps", maxSteps);
        m.put("timeout_seconds", timeoutSeconds);
        m.put("confirm_actions", confirmActions);
        m.put("context_char_budget", contextCharBudget);
        m.put("enforce_scope", enforceScope);
        m.put("agent_mode", agentMode);
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
        if (m.containsKey("provider")) {
            c.provider = normalizeProvider(Json.asString(m.get("provider"), PROVIDER_OLLAMA));
        } else if (Json.asBool(m.get("use_openai_endpoint"), false)) {
            // Migrate settings written by releases that only exposed a checkbox.
            c.provider = PROVIDER_OPENAI;
        }
        c.baseUrl = Json.asString(m.getOrDefault("base_url", c.baseUrl), c.baseUrl);
        c.chatEndpoint = Json.asString(m.getOrDefault(
                "chat_endpoint", defaultChatEndpoint(c.provider)), defaultChatEndpoint(c.provider));
        c.modelsEndpoint = Json.asString(m.getOrDefault(
                "models_endpoint", defaultModelsEndpoint(c.provider)), defaultModelsEndpoint(c.provider));
        c.model = Json.asString(m.getOrDefault("model", c.model), c.model);
        c.apiToken = Json.asString(m.getOrDefault("api_token", c.apiToken), c.apiToken);
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
        c.passiveAiScan = Json.asBool(m.getOrDefault("passive_ai_scan", c.passiveAiScan), c.passiveAiScan);
        return c;
    }

    public String normalizedProvider() {
        return normalizeProvider(provider);
    }

    public boolean usesNativeTools() {
        return !PROVIDER_OLLAMA.equals(normalizedProvider());
    }

    public String providerDisplayName() {
        switch (normalizedProvider()) {
            case PROVIDER_OPENAI:
                return "OpenAI-compatible";
            case PROVIDER_ANTHROPIC:
                return "Anthropic Messages";
            default:
                return "Ollama native";
        }
    }

    public static String defaultBaseUrl(String provider) {
        switch (normalizeProvider(provider)) {
            case PROVIDER_OPENAI:
                return "https://api.openai.com";
            case PROVIDER_ANTHROPIC:
                return "https://api.anthropic.com";
            default:
                return "http://127.0.0.1:11434";
        }
    }

    public static String defaultChatEndpoint(String provider) {
        switch (normalizeProvider(provider)) {
            case PROVIDER_OPENAI:
                return "/v1/chat/completions";
            case PROVIDER_ANTHROPIC:
                return "/v1/messages";
            default:
                return "/api/chat";
        }
    }

    public static String defaultModelsEndpoint(String provider) {
        switch (normalizeProvider(provider)) {
            case PROVIDER_OPENAI:
            case PROVIDER_ANTHROPIC:
                return "/v1/models";
            default:
                return "/api/tags";
        }
    }

    private static String normalizeProvider(String value) {
        String p = value == null ? "" : value.trim().toLowerCase(java.util.Locale.ROOT);
        if (PROVIDER_OPENAI.equals(p) || PROVIDER_ANTHROPIC.equals(p)) {
            return p;
        }
        return PROVIDER_OLLAMA;
    }

    public String normalizedBaseUrl() {
        String u = baseUrl == null ? "" : baseUrl.trim();
        while (u.endsWith("/")) {
            u = u.substring(0, u.length() - 1);
        }
        return u;
    }

    /** Join a provider path while accepting base URLs both with and without /v1. */
    public String endpoint(String path) {
        String base = normalizedBaseUrl();
        String p = path == null || path.isEmpty() ? "/" : (path.startsWith("/") ? path : "/" + path);
        if (base.endsWith("/v1") && p.startsWith("/v1/")) {
            return base + p.substring(3);
        }
        return base + p;
    }

    public String resolvedChatEndpoint() {
        return resolveEndpoint(chatEndpoint, defaultChatEndpoint(provider));
    }

    public String resolvedModelsEndpoint() {
        return resolveEndpoint(modelsEndpoint, defaultModelsEndpoint(provider));
    }

    /** Resolve a relative provider path, while allowing an independent absolute URL. */
    public String resolveEndpoint(String configured, String fallback) {
        String value = configured == null || configured.trim().isEmpty() ? fallback : configured.trim();
        String lower = value.toLowerCase(java.util.Locale.ROOT);
        if (lower.startsWith("https://") || lower.startsWith("http://")) {
            return value;
        }
        return endpoint(value);
    }
}
