/*
 * query_montoya_api: reflectively walks the Montoya API graph starting from
 * MontoyaApi, collecting interface methods, and returns those matching a keyword.
 * Lets the agent discover available API surface without shipping the API source.
 */
package com.cybernexis.agent.tools;

import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import burp.api.montoya.MontoyaApi;

public final class ApiQueryTools {

    private static final String PKG = "burp.api.montoya";
    private static final int MAX_CLASSES = 400;

    private ApiQueryTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "query_montoya_api",
                "Search the Montoya API for interfaces/methods by keyword (matches interface name, method name, or return type). args: query (required), max_results?.",
                false,
                Schema.object()
                        .prop("query", "string", "Keyword, e.g. 'scope', 'sendRequest', 'issue'.")
                        .prop("max_results", "integer", "Maximum matches (default 40).")
                        .require("query")
                        .build(),
                ApiQueryTools::query));
    }

    private static ToolResult query(Map<String, Object> args, ToolContext ctx) {
        String query = Tools.str(args, "query");
        if (query == null || query.isEmpty()) {
            return ToolResult.error("query is required.");
        }
        int limit = Tools.intOr(args, "max_results", 40);
        String q = query.toLowerCase();

        Set<Class<?>> visited = new LinkedHashSet<>();
        Deque<Class<?>> queue = new ArrayDeque<>();
        queue.add(MontoyaApi.class);

        List<Map<String, Object>> matches = new ArrayList<>();
        int total = 0;

        while (!queue.isEmpty() && visited.size() < MAX_CLASSES) {
            Class<?> current = queue.poll();
            if (!visited.add(current)) {
                continue;
            }
            for (Method m : current.getMethods()) {
                if (m.getDeclaringClass() == Object.class) {
                    continue;
                }
                Class<?> ret = m.getReturnType();
                enqueueMontoya(ret, queue);
                for (Class<?> p : m.getParameterTypes()) {
                    enqueueMontoya(p, queue);
                }
                String signature = signature(current, m);
                boolean hit = current.getSimpleName().toLowerCase().contains(q)
                        || m.getName().toLowerCase().contains(q)
                        || ret.getSimpleName().toLowerCase().contains(q);
                if (hit) {
                    total++;
                    if (matches.size() < limit) {
                        Map<String, Object> entry = new LinkedHashMap<>();
                        entry.put("interface", current.getName().replace(PKG + ".", ""));
                        entry.put("signature", signature);
                        matches.add(entry);
                    }
                }
            }
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("query", query);
        data.put("total_matched", total);
        data.put("returned", matches.size());
        data.put("interfaces_scanned", visited.size());
        data.put("matches", matches);
        return ToolResult.ok(data);
    }

    private static void enqueueMontoya(Class<?> type, Deque<Class<?>> queue) {
        Class<?> t = type.isArray() ? type.getComponentType() : type;
        if (t.isInterface() && t.getName().startsWith(PKG)) {
            queue.add(t);
        }
    }

    private static String signature(Class<?> owner, Method m) {
        StringBuilder sb = new StringBuilder();
        sb.append(m.getReturnType().getSimpleName()).append(' ');
        sb.append(m.getName()).append('(');
        Class<?>[] params = m.getParameterTypes();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(params[i].getSimpleName());
        }
        sb.append(')');
        return sb.toString();
    }
}
