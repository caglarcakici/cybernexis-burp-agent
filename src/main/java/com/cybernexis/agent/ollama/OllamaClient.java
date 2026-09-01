/*
 * HTTP client for a local Ollama server. Supports streaming chat over the
 * native /api/chat endpoint and the OpenAI-compatible /v1/chat/completions
 * endpoint (with native tool calling). Uses only the JDK HttpClient.
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

    /** GET {base}/api/version — quick connectivity check. Returns version or throws. */
    public String version() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(config.normalizedBaseUrl() + "/api/version"))
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

    /** GET {base}/api/tags — list installed model names. */
    public List<String> listModels() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(config.normalizedBaseUrl() + "/api/tags"))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        List<String> names = new ArrayList<>();
        Map<String, Object> body = Json.asMap(Json.parse(resp.body()));
        for (Object m : Json.asList(body.get("models"))) {
            Object name = Json.asMap(m).get("name");
            if (name != null) {
                names.add(String.valueOf(name));
            }
        }
        return names;
    }

    /**
     * Stream a chat turn. {@code tools} may be null/empty. Returns the aggregated
     * assistant content plus any native tool calls (only when using the OpenAI endpoint).
     */
    public ChatResult streamChat(List<Map<String, Object>> messages,
                                 List<Map<String, Object>> tools,
                                 TokenListener listener,
                                 CancelToken cancel) throws IOException, InterruptedException {
        if (config.useOpenAiEndpoint) {
            return streamOpenAi(messages, tools, listener, cancel);
        }
        return streamNative(messages, listener, cancel);
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

        HttpResponse<InputStream> resp = post("/api/chat", Json.write(body), cancel);
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
                    throw new IOException("Ollama error: " + obj.get("error"));
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

        HttpResponse<InputStream> resp = post("/v1/chat/completions", Json.write(body), cancel);
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
                    throw new IOException("Ollama error: " + obj.get("error"));
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

    // ---- Low-level helpers --------------------------------------------------

    private HttpResponse<InputStream> post(String path, String jsonBody, CancelToken cancel)
            throws IOException, InterruptedException {
        // No total-request timeout on purpose: streaming turns can legitimately run
        // for minutes on large models. An IdleGuard aborts only when the server
        // stops producing tokens for config.timeoutSeconds; slow-but-alive
        // generations are never cut off mid-answer.
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(config.normalizedBaseUrl() + path))
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
