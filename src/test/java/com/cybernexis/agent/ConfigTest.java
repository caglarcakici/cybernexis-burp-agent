package com.cybernexis.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ConfigTest {

    @Test
    void migratesLegacyOpenAiCheckbox() {
        Config config = Config.fromJson("{\"base_url\":\"https://gateway.example/v1\","
                + "\"use_openai_endpoint\":true}");

        assertEquals(Config.PROVIDER_OPENAI, config.normalizedProvider());
        assertTrue(config.usesNativeTools());
        assertEquals("https://gateway.example/v1/chat/completions",
                config.endpoint("/v1/chat/completions"));
    }

    @Test
    void persistsProviderAndToken() {
        Config config = new Config();
        config.provider = Config.PROVIDER_ANTHROPIC;
        config.baseUrl = "https://api.anthropic.com/";
        config.chatEndpoint = Config.defaultChatEndpoint(config.provider);
        config.modelsEndpoint = Config.defaultModelsEndpoint(config.provider);
        config.apiToken = "secret-token";

        Config restored = Config.fromJson(config.toJson());

        assertEquals(Config.PROVIDER_ANTHROPIC, restored.normalizedProvider());
        assertEquals("secret-token", restored.apiToken);
        assertEquals("https://api.anthropic.com/v1/messages", restored.endpoint("/v1/messages"));
    }

    @Test
    void resolvesIndependentDeepSeekEndpoints() {
        Config config = new Config();
        config.provider = Config.PROVIDER_OPENAI;
        config.baseUrl = "https://api.deepseek.com";
        config.chatEndpoint = "/chat/completions";
        config.modelsEndpoint = "https://models-gateway.example/models";

        assertEquals("https://api.deepseek.com/chat/completions", config.resolvedChatEndpoint());
        assertEquals("https://models-gateway.example/models", config.resolvedModelsEndpoint());
    }
}
