/*
 * Per-task named variables. Placeholders {{name}} in tool arguments (url, body,
 * headers, path) are replaced at send time. Reserved names used by brute_force
 * (pass / password / user / username) are left untouched so payload markers survive.
 */
package com.cybernexis.agent.tools;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class VarStore {

    static final Set<String> RESERVED = Set.of("pass", "password", "user", "username");

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{([A-Za-z_][A-Za-z0-9_]*)\\}\\}");

    private final Map<String, String> values = new LinkedHashMap<>();

    public synchronized String get(String name) {
        return name == null ? null : values.get(normalize(name));
    }

    public synchronized void set(String name, String value) {
        String n = normalize(name);
        if (n == null) {
            return;
        }
        if (value == null) {
            values.remove(n);
        } else {
            values.put(n, value);
        }
    }

    public synchronized Map<String, String> snapshot() {
        return new LinkedHashMap<>(values);
    }

    public synchronized void restore(Map<String, String> incoming) {
        values.clear();
        if (incoming == null) {
            return;
        }
        for (Map.Entry<String, String> e : incoming.entrySet()) {
            set(e.getKey(), e.getValue());
        }
    }

    public synchronized boolean isEmpty() {
        return values.isEmpty();
    }

    /**
     * Replace {{name}} with stored values. Unknown names and reserved brute_force
     * markers are left as-is.
     */
    public String interpolate(String text) {
        if (text == null || text.indexOf('{') < 0) {
            return text;
        }
        Map<String, String> snap;
        synchronized (this) {
            snap = values.isEmpty() ? Collections.emptyMap() : new LinkedHashMap<>(values);
        }
        if (snap.isEmpty() && text.indexOf("{{") < 0) {
            return text;
        }
        Matcher m = PLACEHOLDER.matcher(text);
        StringBuffer out = new StringBuffer();
        while (m.find()) {
            String key = m.group(1);
            if (RESERVED.contains(key.toLowerCase())) {
                m.appendReplacement(out, Matcher.quoteReplacement(m.group(0)));
                continue;
            }
            String val = snap.get(key.toLowerCase());
            m.appendReplacement(out, Matcher.quoteReplacement(val != null ? val : m.group(0)));
        }
        m.appendTail(out);
        return out.toString();
    }

    static String normalize(String name) {
        if (name == null) {
            return null;
        }
        String n = name.trim();
        if (n.startsWith("{{") && n.endsWith("}}") && n.length() > 4) {
            n = n.substring(2, n.length() - 2).trim();
        }
        if (n.isEmpty() || !n.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            return null;
        }
        return n.toLowerCase();
    }
}
