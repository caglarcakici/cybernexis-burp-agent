/*
 * Provider-neutral model HTTP client. Supports Ollama native chat,
 * OpenAI-compatible Chat Completions, and Anthropic Messages with streaming
 * tool calls. Uses only the JDK HttpClient.
 */
package com.cybernexis.agent.ollama;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.cybernexis.agent.Config;
import com.cybernexis.agent.json.Json;

public class OllamaClient {

    /** Receives streamed assistant text tokens as they arrive. */
    public interface TokenListener {
        void onToken(String text);
    }

    /** Cooperative cancellation handle. Closing the stream aborts the read. */
    public static final class CancelToken {
        private volatile boolean cancelled;
        private volatile InputStream stream;

        public void cancel() {
            cancelled = true;
            InputStream s = stream;
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ignored) {
                }
            }
        }

        public boolean isCancelled() {
            return cancelled;
        }

        void bind(InputStream s) {
            this.stream = s;
        }
    }

    /** Aggregated result of one streamed chat turn. */
    public static final class ChatResult {
        public final String content;
        public final List<ToolCallRaw> toolCalls;
        /** True when the turn was cut short by the idle guard (server stopped emitting tokens). */
        public final boolean timedOut;

        public ChatResult(String content, List<ToolCallRaw> toolCalls) {
            this(content, toolCalls, false);
        }

        public ChatResult(String content, List<ToolCallRaw> toolCalls, boolean timedOut) {
            this.content = content;
            this.toolCalls = toolCalls;
            this.timedOut = timedOut;
        }
    }

    /** A native (OpenAI-style) tool call: function name + raw JSON arguments string. */
    public static final class ToolCallRaw {
        public final String name;
        public final String arguments;

        public ToolCallRaw(String name, String arguments) {
            this.name = name;
            this.arguments = arguments;
        }
    }

    private final Config config;
    private final HttpClient http;

    public OllamaClient(Config config) {
        this.config = config;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /** Quick provider-specific connectivity check. */
    public String connectionSummary() throws IOException, InterruptedException {
        if (Config.PROVIDER_OLLAMA.equals(config.normalizedProvider())) {
            return "Ollama v" + version();
        }
        return config.providerDisplayName();
    }

    /** GET {base}/api/version — Ollama connectivity check. */
    public String version() throws IOException, InterruptedException {
        HttpRequest req = requestBuilder("/api/version")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new IOException("HTTP " + resp.statusCode() + ": " + resp.body());
        }
        Object v = Json.asMap(Json.parse(resp.body())).get("version");
        return v == null ? resp.body() : String.valueOf(v);
    }

    /** List models using the selected provider's discovery endpoint. */
    public List<String> listModels() throws IOException, InterruptedException {
        boolean ollama = Config.PROVIDER_OLLAMA.equals(config.normalizedProvider());
        String endpoint = config.resolvedModelsEndpoint();
        HttpRequest req = requestBuilder(endpoint)
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new IOException("HTTP " + resp.statusCode() + " from " + endpoint + ": " + resp.body());
        }
        List<String> names = new ArrayList<>();
        Map<String, Object> body = Json.asMap(Json.parse(resp.body()));
        for (Object m : Json.asList(body.get(ollama ? "models" : "data"))) {
            Map<String, Object> model = Json.asMap(m);
            Object name = model.get(ollama ? "name" : "id");
            if (name != null) {
                names.add(String.valueOf(name));
            }
        }
        return names;
    }

    /**
     * Stream a chat turn. {@code tools} may be null/empty. Returns the aggregated
     * assistant content plus any native tool calls.
     */
    public ChatResult streamChat(List<Map<String, Object>> messages,
                                 List<Map<String, Object>> tools,
                                 TokenListener listener,
                                 CancelToken cancel) throws IOException, InterruptedException {
        switch (config.normalizedProvider()) {
            case Config.PROVIDER_OPENAI:
                return streamOpenAi(messages, tools, listener, cancel);
            case Config.PROVIDER_ANTHROPIC:
                return streamAnthropic(messages, tools, listener, cancel);
            default:
                return streamNative(messages, listener, cancel);
        }
    }

    // ---- Native Ollama /api/chat -------------------------------------------

    private ChatResult streamNative(List<Map<String, Object>> messages,
                                    TokenListener listener,
                                    CancelToken cancel) throws IOException, InterruptedException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", config.model);
        body.put("stream", true);
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("temperature", config.temperature);
        options.put("num_predict", config.maxTokens);
        body.put("options", options);
        body.put("messages", messages);

        HttpResponse<InputStream> resp = post(config.resolvedChatEndpoint(), Json.write(body), cancel);
        StringBuilder content = new StringBuilder();
        InputStream in = resp.body();
        IdleGuard guard = new IdleGuard(in, config.timeoutSeconds, cancel);
        guard.start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                guard.activity();
                if (cancel != null && cancel.isCancelled()) {
                    break;
                }
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                Map<String, Object> obj = Json.parseObject(line);
                if (obj.containsKey("error")) {
                    throw providerError(obj.get("error"));
                }
                Object message = obj.get("message");
                if (message instanceof Map) {
                    Object c = ((Map<?, ?>) message).get("content");
                    if (c != null) {
                        String token = String.valueOf(c);
                        content.append(token);
                        if (listener != null && !token.isEmpty()) {
                            listener.onToken(token);
                        }
                    }
                }
                if (Boolean.TRUE.equals(obj.get("done"))) {
                    break;
                }
            }
        } catch (IOException e) {
            // Salvage whatever was generated on cancel or idle-timeout instead of losing it.
            if (guard.timedOut()) {
                return new ChatResult(content.toString(), new ArrayList<>(), true);
            }
            if (cancel != null && cancel.isCancelled()) {
                return new ChatResult(content.toString(), new ArrayList<>());
            }
            throw e;
        } finally {
            guard.stop();
        }
        return new ChatResult(content.toString(), new ArrayList<>());
    }

    // ---- OpenAI-compatible /v1/chat/completions ----------------------------

    private ChatResult streamOpenAi(List<Map<String, Object>> messages,
                                    List<Map<String, Object>> tools,
                                    TokenListener listener,
                                    CancelToken cancel) throws IOException, InterruptedException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", config.model);
        body.put("stream", true);
        body.put("temperature", config.temperature);
        body.put("max_tokens", config.maxTokens);
        body.put("messages", messages);
        if (tools != null && !tools.isEmpty()) {
            body.put("tools", tools);
            body.put("tool_choice", "auto");
        }

        HttpResponse<InputStream> resp = post(config.resolvedChatEndpoint(), Json.write(body), cancel);
        StringBuilder content = new StringBuilder();
        // tool call fragments accumulated by index
        TreeMap<Integer, StringBuilder> toolArgs = new TreeMap<>();
        TreeMap<Integer, String> toolNames = new TreeMap<>();

        InputStream in = resp.body();
        IdleGuard guard = new IdleGuard(in, config.timeoutSeconds, cancel);
        guard.start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                guard.activity();
                if (cancel != null && cancel.isCancelled()) {
                    break;
                }
                line = line.trim();
                if (line.isEmpty() || !line.startsWith("data:")) {
                    continue;
                }
                String data = line.substring("data:".length()).trim();
                if (data.equals("[DONE]")) {
                    break;
                }
                Map<String, Object> obj = Json.parseObject(data);
                if (obj.containsKey("error")) {
                    throw providerError(obj.get("error"));
                }
                List<Object> choices = Json.asList(obj.get("choices"));
                if (choices.isEmpty()) {
                    continue;
                }
                Map<String, Object> delta = Json.asMap(Json.asMap(choices.get(0)).get("delta"));
                Object c = delta.get("content");
                if (c != null) {
                    String token = String.valueOf(c);
                    content.append(token);
                    if (listener != null && !token.isEmpty()) {
                        listener.onToken(token);
                    }
                }
                for (Object tcObj : Json.asList(delta.get("tool_calls"))) {
                    Map<String, Object> tc = Json.asMap(tcObj);
                    int idx = Json.asInt(tc.getOrDefault("index", 0), 0);
                    Map<String, Object> fn = Json.asMap(tc.get("function"));
                    Object name = fn.get("name");
                    if (name != null) {
                        toolNames.put(idx, String.valueOf(name));
                    }
                    Object args = fn.get("arguments");
                    if (args != null) {
                        toolArgs.computeIfAbsent(idx, k -> new StringBuilder()).append(args);
                    }
                }
            }
        } catch (IOException e) {
            // Salvage partial output on cancel or idle-timeout rather than discarding it.
            if ((cancel == null || !cancel.isCancelled()) && !guard.timedOut()) {
                throw e;
            }
        } finally {
            guard.stop();
        }

        List<ToolCallRaw> calls = new ArrayList<>();
        for (Map.Entry<Integer, String> e : toolNames.entrySet()) {
            StringBuilder a = toolArgs.get(e.getKey());
            calls.add(new ToolCallRaw(e.getValue(), a == null ? "{}" : a.toString()));
        }
        return new ChatResult(content.toString(), calls, guard.timedOut());
    }

    // ---- Anthropic Messages /v1/messages ----------------------------------

    private ChatResult streamAnthropic(List<Map<String, Object>> messages,
                                       List<Map<String, Object>> tools,
                                       TokenListener listener,
                                       CancelToken cancel) throws IOException, InterruptedException {
        Map<String, Object> body = anthropicBody(messages, tools);
        HttpResponse<InputStream> resp = post(config.resolvedChatEndpoint(), Json.write(body), cancel);

        StringBuilder content = new StringBuilder();
        TreeMap<Integer, StringBuilder> toolArgs = new TreeMap<>();
        TreeMap<Integer, String> toolNames = new TreeMap<>();

        InputStream in = resp.body();
        IdleGuard guard = new IdleGuard(in, config.timeoutSeconds, cancel);
        guard.start();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                guard.activity();
                if (cancel != null && cancel.isCancelled()) {
                    break;
                }
                line = line.trim();
                if (line.isEmpty() || !line.startsWith("data:")) {
                    continue;
                }
                String data = line.substring("data:".length()).trim();
                if (data.isEmpty() || data.equals("[DONE]")) {
                    continue;
                }
                Map<String, Object> obj = Json.parseObject(data);
                if (obj.containsKey("error") || "error".equals(obj.get("type"))) {
                    throw providerError(obj.get("error"));
                }
                String type = Json.asString(obj.get("type"), "");
                int idx = Json.asInt(obj.getOrDefault("index", 0), 0);
                if ("content_block_start".equals(type)) {
                    Map<String, Object> block = Json.asMap(obj.get("content_block"));
                    String blockType = Json.asString(block.get("type"), "");
                    if ("text".equals(blockType)) {
                        emit(Json.asString(block.get("text"), ""), content, listener);
                    } else if ("tool_use".equals(blockType)) {
                        toolNames.put(idx, Json.asString(block.get("name"), ""));
                        Map<String, Object> initial = Json.asMap(block.get("input"));
                        if (!initial.isEmpty()) {
                            toolArgs.computeIfAbsent(idx, k -> new StringBuilder()).append(Json.write(initial));
                        }
                    }
                } else if ("content_block_delta".equals(type)) {
                    Map<String, Object> delta = Json.asMap(obj.get("delta"));
                    String deltaType = Json.asString(delta.get("type"), "");
                    if ("text_delta".equals(deltaType)) {
                        emit(Json.asString(delta.get("text"), ""), content, listener);
                    } else if ("input_json_delta".equals(deltaType)) {
                        toolArgs.computeIfAbsent(idx, k -> new StringBuilder())
                                .append(Json.asString(delta.get("partial_json"), ""));
                    }
                } else if ("message_stop".equals(type)) {
                    break;
                }
            }
        } catch (IOException e) {
            if ((cancel == null || !cancel.isCancelled()) && !guard.timedOut()) {
                throw e;
            }
        } finally {
            guard.stop();
        }

        List<ToolCallRaw> calls = new ArrayList<>();
        for (Map.Entry<Integer, String> e : toolNames.entrySet()) {
            if (e.getValue() == null || e.getValue().isEmpty()) {
                continue;
            }
            StringBuilder a = toolArgs.get(e.getKey());
            calls.add(new ToolCallRaw(e.getValue(), a == null || a.length() == 0 ? "{}" : a.toString()));
        }
        return new ChatResult(content.toString(), calls, guard.timedOut());
    }

    private Map<String, Object> anthropicBody(List<Map<String, Object>> messages,
                                              List<Map<String, Object>> tools) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", config.model);
        body.put("stream", true);
        body.put("temperature", config.temperature);
        body.put("max_tokens", config.maxTokens);

        StringBuilder system = new StringBuilder();
        List<Map<String, Object>> convertedMessages = new ArrayList<>();
        for (Map<String, Object> message : messages) {
            String role = Json.asString(message.get("role"), "user");
            String text = Json.asString(message.get("content"), "");
            if ("system".equals(role)) {
                if (system.length() > 0) {
                    system.append('\n');
                }
                system.append(text);
            } else {
                Map<String, Object> converted = new LinkedHashMap<>();
                converted.put("role", "assistant".equals(role) ? "assistant" : "user");
                converted.put("content", text);
                convertedMessages.add(converted);
            }
        }
        if (system.length() > 0) {
            body.put("system", system.toString());
        }
        body.put("messages", convertedMessages);

        if (tools != null && !tools.isEmpty()) {
            List<Map<String, Object>> anthropicTools = new ArrayList<>();
            for (Map<String, Object> tool : tools) {
                Map<String, Object> fn = Json.asMap(tool.get("function"));
                if (fn.isEmpty()) {
                    continue;
                }
                Map<String, Object> converted = new LinkedHashMap<>();
                converted.put("name", fn.get("name"));
                converted.put("description", fn.get("description"));
                converted.put("input_schema", fn.get("parameters"));
                anthropicTools.add(converted);
            }
            body.put("tools", anthropicTools);
            Map<String, Object> choice = new LinkedHashMap<>();
            choice.put("type", "auto");
            body.put("tool_choice", choice);
        }
        return body;
    }

    // ---- Low-level helpers --------------------------------------------------

    private HttpResponse<InputStream> post(String path, String jsonBody, CancelToken cancel)
            throws IOException, InterruptedException {
        // No total-request timeout on purpose: streaming turns can legitimately run
        // for minutes on large models. An IdleGuard aborts only when the server
        // stops producing tokens for config.timeoutSeconds; slow-but-alive
        // generations are never cut off mid-answer.
        HttpRequest req = requestBuilder(path)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                .build();
        HttpResponse<InputStream> resp = http.send(req, HttpResponse.BodyHandlers.ofInputStream());
        if (cancel != null) {
            cancel.bind(resp.body());
        }
        if (resp.statusCode() / 100 != 2) {
            String err = readAll(resp.body());
            throw new IOException("HTTP " + resp.statusCode() + " from " + path + ": " + err);
        }
        return resp;
    }

    private HttpRequest.Builder requestBuilder(String path) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(config.resolveEndpoint(path, path)));
        String token = config.apiToken == null ? "" : config.apiToken.trim();
        if (!token.isEmpty()) {
            if (Config.PROVIDER_ANTHROPIC.equals(config.normalizedProvider())) {
                builder.header("x-api-key", token);
            } else {
                builder.header("Authorization", "Bearer " + token);
            }
        }
        if (Config.PROVIDER_ANTHROPIC.equals(config.normalizedProvider())) {
            builder.header("anthropic-version", "2023-06-01");
        }
        return builder;
    }

    private IOException providerError(Object error) {
        if (error instanceof Map) {
            Map<String, Object> e = Json.asMap(error);
            Object message = e.get("message");
            if (message != null) {
                return new IOException(config.providerDisplayName() + " error: " + message);
            }
        }
        return new IOException(config.providerDisplayName() + " error: " + String.valueOf(error));
    }

    private static void emit(String token, StringBuilder content, TokenListener listener) {
        if (token == null || token.isEmpty()) {
            return;
        }
        content.append(token);
        if (listener != null) {
            listener.onToken(token);
        }
    }

    /**
     * Aborts a streaming read when the server goes silent. Unlike a total-request
     * timeout, this only fires after {@code idleSeconds} elapse with no new token,
     * so a slow model streaming a long answer is never cut off. On trip it closes
     * the underlying stream (unblocking the reader) and records {@link #timedOut()}
     * so the caller can salvage whatever was received.
     */
    private static final class IdleGuard {
        private final InputStream stream;
        private final long idleNanos;
        private final CancelToken cancel;
        private final java.util.concurrent.atomic.AtomicLong lastActivity =
                new java.util.concurrent.atomic.AtomicLong(System.nanoTime());
        private final java.util.concurrent.atomic.AtomicBoolean timedOut =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        private volatile boolean done;
        private final Thread thread;

        IdleGuard(InputStream stream, int idleSeconds, CancelToken cancel) {
            this.stream = stream;
            this.idleNanos = Duration.ofSeconds(Math.max(5, idleSeconds)).toNanos();
            this.cancel = cancel;
            this.thread = new Thread(this::watch, "cybernexis-ollama-idle-guard");
            this.thread.setDaemon(true);
        }

        void start() {
            thread.start();
        }

        void activity() {
            lastActivity.set(System.nanoTime());
        }

        void stop() {
            done = true;
            thread.interrupt();
        }

        boolean timedOut() {
            return timedOut.get();
        }

        private void watch() {
            while (!done) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    return;
                }
                if (done || (cancel != null && cancel.isCancelled())) {
                    return;
                }
                if (System.nanoTime() - lastActivity.get() > idleNanos) {
                    timedOut.set(true);
                    try {
                        stream.close();
                    } catch (IOException ignored) {
                    }
                    return;
                }
            }
        }
    }

    private static String readAll(InputStream in) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        } catch (IOException e) {
            return "<unreadable body>";
        }
    }
}
