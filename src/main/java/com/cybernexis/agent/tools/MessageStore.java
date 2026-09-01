/*
 * In-memory index of HTTP messages the agent can reference by integer id.
 * Proxy-history items keep their native Burp history id; sitemap items and
 * requests sent by the agent get synthetic ids so they remain stable per session.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class MessageStore {

    public static final class Entry {
        public final int id;
        public final HttpRequestResponse message;
        public final String source;

        Entry(int id, HttpRequestResponse message, String source) {
            this.id = id;
            this.message = message;
            this.source = source;
        }
    }

    private final Map<Integer, Entry> byId = new LinkedHashMap<>();
    private final Map<String, Integer> sitemapKeyToId = new LinkedHashMap<>();
    private int nextSynthetic = 1_000_000;

    /** Pull the latest proxy history and sitemap into the store. */
    public synchronized void refresh(MontoyaApi api) {
        try {
            for (ProxyHttpRequestResponse phrr : api.proxy().history()) {
                int id = phrr.id();
                if (!byId.containsKey(id)) {
                    HttpRequestResponse hrr = HttpRequestResponse.httpRequestResponse(
                            phrr.finalRequest(), phrr.response());
                    byId.put(id, new Entry(id, hrr, "proxy"));
                }
            }
        } catch (RuntimeException ignored) {
            // proxy history may be unavailable in some editions; ignore
        }
        try {
            for (HttpRequestResponse hrr : api.siteMap().requestResponses()) {
                String key = keyOf(hrr);
                if (!sitemapKeyToId.containsKey(key)) {
                    int id = nextSynthetic++;
                    sitemapKeyToId.put(key, id);
                    byId.put(id, new Entry(id, hrr, "sitemap"));
                }
            }
        } catch (RuntimeException ignored) {
        }
    }

    public synchronized int register(HttpRequestResponse hrr, String source) {
        int id = nextSynthetic++;
        byId.put(id, new Entry(id, hrr, source));
        return id;
    }

    public synchronized Entry get(int id) {
        return byId.get(id);
    }

    public synchronized List<Entry> all() {
        return new ArrayList<>(byId.values());
    }

    private static String keyOf(HttpRequestResponse hrr) {
        try {
            return hrr.request().method() + " " + hrr.request().url();
        } catch (RuntimeException e) {
            return String.valueOf(System.identityHashCode(hrr));
        }
    }
}
