package com.cybernexis.agent.ollama;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.cybernexis.agent.Config;
import com.cybernexis.agent.json.Json;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class OllamaClientTest {

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void sendsBearerTokenAndParsesOpenAiToolStream() throws Exception {
        AtomicReference<String> auth = new AtomicReference<>();
        AtomicReference<String> requestBody = new AtomicReference<>();
        startServer("/chat/completions", exchange -> {
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(exchange, "data: {\"choices\":[{\"delta\":{\"content\":\"Checking. \"}}]}\n\n"
                    + "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,"
                    + "\"function\":{\"name\":\"inspect_scope\",\"arguments\":\"{\"}}]}}]}\n\n"
                    + "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,"
                    + "\"function\":{\"arguments\":\"}\"}}]}}]}\n\n"
                    + "data: [DONE]\n\n");
        });

        Config config = config(Config.PROVIDER_OPENAI, "openai-secret");
        config.chatEndpoint = "/chat/completions";
        OllamaClient.ChatResult result = new OllamaClient(config).streamChat(
                messages(), tools(), null, new OllamaClient.CancelToken());

        assertEquals("Bearer openai-secret", auth.get());
        assertTrue(requestBody.get().contains("\"tool_choice\":\"auto\""));
        assertEquals("Checking. ", result.content);
        assertEquals(1, result.toolCalls.size());
        assertEquals("inspect_scope", result.toolCalls.get(0).name);
        assertEquals("{}", result.toolCalls.get(0).arguments);
    }

    @Test
    void listsModelsFromIndependentEndpoint() throws Exception {
        AtomicReference<String> auth = new AtomicReference<>();
        startServer("/models", exchange -> {
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] bytes = ("{\"object\":\"list\",\"data\":["
                    + "{\"id\":\"deepseek-v4-pro\",\"object\":\"model\"}]}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });

        Config config = config(Config.PROVIDER_OPENAI, "deepseek-secret");
        config.chatEndpoint = "/chat/completions";
        config.modelsEndpoint = "/models";

        List<String> models = new OllamaClient(config).listModels();

        assertEquals("Bearer deepseek-secret", auth.get());
        assertEquals(1, models.size());
        assertEquals("deepseek-v4-pro", models.get(0));
    }

    @Test
    void convertsAndParsesAnthropicMessagesProtocol() throws Exception {
        AtomicReference<String> apiKey = new AtomicReference<>();
        AtomicReference<String> version = new AtomicReference<>();
        AtomicReference<Map<String, Object>> requestBody = new AtomicReference<>();
        startServer("/v1/messages", exchange -> {
            apiKey.set(exchange.getRequestHeaders().getFirst("x-api-key"));
            version.set(exchange.getRequestHeaders().getFirst("anthropic-version"));
            requestBody.set(Json.parseObject(new String(
                    exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            respond(exchange, "event: content_block_start\n"
                    + "data: {\"type\":\"content_block_start\",\"index\":0,"
                    + "\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
                    + "event: content_block_delta\n"
                    + "data: {\"type\":\"content_block_delta\",\"index\":0,"
                    + "\"delta\":{\"type\":\"text_delta\",\"text\":\"Checking.\"}}\n\n"
                    + "event: content_block_start\n"
                    + "data: {\"type\":\"content_block_start\",\"index\":1,"
                    + "\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\","
                    + "\"name\":\"inspect_scope\",\"input\":{}}}\n\n"
                    + "event: content_block_delta\n"
                    + "data: {\"type\":\"content_block_delta\",\"index\":1,"
                    + "\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n"
                    + "event: message_stop\n"
                    + "data: {\"type\":\"message_stop\"}\n\n");
        });

        Config config = config(Config.PROVIDER_ANTHROPIC, "anthropic-secret");
        OllamaClient.ChatResult result = new OllamaClient(config).streamChat(
                messages(), tools(), null, new OllamaClient.CancelToken());

        assertEquals("anthropic-secret", apiKey.get());
        assertEquals("2023-06-01", version.get());
        assertEquals("system prompt", requestBody.get().get("system"));
        List<Object> sentMessages = Json.asList(requestBody.get().get("messages"));
        assertEquals(1, sentMessages.size());
        assertEquals("user", Json.asMap(sentMessages.get(0)).get("role"));
        List<Object> sentTools = Json.asList(requestBody.get().get("tools"));
        assertFalse(sentTools.isEmpty());
        assertTrue(Json.asMap(sentTools.get(0)).containsKey("input_schema"));
        assertFalse(Json.asMap(sentTools.get(0)).containsKey("function"));
        assertEquals("Checking.", result.content);
        assertEquals("inspect_scope", result.toolCalls.get(0).name);
        assertEquals("{}", result.toolCalls.get(0).arguments);
    }

    private Config config(String provider, String token) {
        Config config = new Config();
        config.provider = provider;
        config.baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        config.chatEndpoint = Config.defaultChatEndpoint(provider);
        config.modelsEndpoint = Config.defaultModelsEndpoint(provider);
        config.model = "test-model";
        config.apiToken = token;
        return config;
    }

    private void startServer(String path, ExchangeHandler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(path, exchange -> handler.handle(exchange));
        server.start();
    }

    private static void respond(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static List<Map<String, Object>> messages() {
        List<Map<String, Object>> messages = new ArrayList<>();
        messages.add(message("system", "system prompt"));
        messages.add(message("user", "inspect the scope"));
        return messages;
    }

    private static Map<String, Object> message(String role, String content) {
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("role", role);
        message.put("content", content);
        return message;
    }

    private static List<Map<String, Object>> tools() {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("type", "object");
        params.put("properties", new LinkedHashMap<String, Object>());
        Map<String, Object> function = new LinkedHashMap<>();
        function.put("name", "inspect_scope");
        function.put("description", "Inspect scope");
        function.put("parameters", params);
        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("type", "function");
        tool.put("function", function);
        List<Map<String, Object>> tools = new ArrayList<>();
        tools.add(tool);
        return tools;
    }

    @FunctionalInterface
    private interface ExchangeHandler {
        void handle(HttpExchange exchange) throws IOException;
    }
}
