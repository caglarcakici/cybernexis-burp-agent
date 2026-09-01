/*
 * Per-task host focus. A new chat task is about one host (www. counts as the
 * same host); sibling subdomains and other in-scope origins from older tasks
 * stay out unless the user names them.
 */
package com.cybernexis.agent.tools;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Focus {

    private static final Pattern URL = Pattern.compile("https?://([^/\\s\"'<>]+)", Pattern.CASE_INSENSITIVE);

    private Focus() {
    }

    public static String inferHost(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        Matcher m = URL.matcher(text);
        if (!m.find()) {
            return null;
        }
        return normalize(m.group(1));
    }

    public static String hostOf(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        try {
            return normalize(java.net.URI.create(url).getHost());
        } catch (RuntimeException e) {
            Matcher m = URL.matcher(url);
            return m.find() ? normalize(m.group(1)) : null;
        }
    }

    /** Lowercase, strip a leading www., drop a trailing dot or :port. */
    public static String normalize(String host) {
        if (host == null) {
            return null;
        }
        String h = host.trim().toLowerCase();
        int colon = h.indexOf(':');
        if (colon > 0) {
            h = h.substring(0, colon);
        }
        if (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.startsWith("www.")) {
            h = h.substring(4);
        }
        return h.isEmpty() ? null : h;
    }

    public static boolean urlMatches(String url, String focusHost) {
        if (focusHost == null || focusHost.isEmpty()) {
            return true;
        }
        return hostMatches(hostOf(url), focusHost);
    }

    public static boolean hostMatches(String host, String focusHost) {
        if (focusHost == null || focusHost.isEmpty()) {
            return true;
        }
        String a = normalize(host);
        String b = normalize(focusHost);
        return a != null && a.equals(b);
    }
}
