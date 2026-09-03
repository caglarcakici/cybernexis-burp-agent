/*
 * User-facing labels for tool chips and approval prompts. Wire names stay
 * snake_case for the model; only the UI converts them.
 */
package com.cybernexis.agent.tools;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class ToolNames {

    private static final Set<String> SMALL_WORDS = new HashSet<>();
    private static final Map<String, String> ACRONYMS = new HashMap<>();

    static {
        for (String w : new String[]{
                "a", "an", "and", "as", "at", "by", "for", "from", "in", "of", "on", "or", "the", "to", "via", "with"
        }) {
            SMALL_WORDS.add(w);
        }
        ACRONYMS.put("api", "API");
        ACRONYMS.put("csrf", "CSRF");
        ACRONYMS.put("dns", "DNS");
        ACRONYMS.put("html", "HTML");
        ACRONYMS.put("http", "HTTP");
        ACRONYMS.put("https", "HTTPS");
        ACRONYMS.put("id", "ID");
        ACRONYMS.put("ids", "IDs");
        ACRONYMS.put("ip", "IP");
        ACRONYMS.put("json", "JSON");
        ACRONYMS.put("jwt", "JWT");
        ACRONYMS.put("ssh", "SSH");
        ACRONYMS.put("ssl", "SSL");
        ACRONYMS.put("tls", "TLS");
        ACRONYMS.put("url", "URL");
        ACRONYMS.put("urls", "URLs");
    }

    private ToolNames() {
    }

    public static String displayName(String wireName) {
        if (wireName == null) {
            return "";
        }
        String trimmed = wireName.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        String[] parts = trimmed.split("[_\\s]+");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(titleToken(parts[i], sb.length() == 0));
        }
        return sb.toString();
    }

    private static String titleToken(String raw, boolean first) {
        String key = raw.toLowerCase(Locale.ROOT);
        String acronym = ACRONYMS.get(key);
        if (acronym != null) {
            return acronym;
        }
        if (!first && SMALL_WORDS.contains(key)) {
            return key;
        }
        return Character.toUpperCase(key.charAt(0)) + key.substring(1);
    }
}
