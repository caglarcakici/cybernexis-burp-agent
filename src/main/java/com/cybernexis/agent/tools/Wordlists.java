/*
 * Built-in wordlists loaded from the jar. The model must NEVER emit hundreds of
 * passwords itself — it picks a list name and brute_force consumes it.
 */
package com.cybernexis.agent.tools;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Wordlists {

    public static final String PASSWORDS_TOP100 = "passwords-top100";
    public static final String PASSWORDS_TOP250 = "passwords-top250";
    public static final String PASSWORDS_TOP500 = "passwords-top500";
    public static final String USERNAMES_COMMON = "usernames-common";

    private static volatile List<String> passwords;
    private static volatile List<String> usernames;

    private Wordlists() {
    }

    public static List<Map<String, Object>> catalog() {
        ensureLoaded();
        List<Map<String, Object>> out = new ArrayList<>();
        out.add(entry(PASSWORDS_TOP100, "Most common passwords (first 100).", slice(passwords, 100).size()));
        out.add(entry(PASSWORDS_TOP250, "Most common passwords (first 250). Default for login brute-force.",
                slice(passwords, 250).size()));
        out.add(entry(PASSWORDS_TOP500, "Most common passwords (first 500).", slice(passwords, 500).size()));
        out.add(entry(USERNAMES_COMMON, "Common login names (admin, test, root, ...).", usernames.size()));
        return out;
    }

    /**
     * Resolve a wordlist name. Unknown names throw IllegalArgumentException with the catalog.
     */
    public static List<String> load(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("wordlist name is empty.");
        }
        ensureLoaded();
        String key = name.trim().toLowerCase();
        switch (key) {
            case "passwords-top100":
            case "top100":
            case "passwords100":
                return slice(passwords, 100);
            case "passwords-top250":
            case "top250":
            case "passwords250":
            case "passwords":
                return slice(passwords, 250);
            case "passwords-top500":
            case "top500":
            case "passwords500":
                return slice(passwords, 500);
            case "usernames-common":
            case "usernames":
            case "users":
                return new ArrayList<>(usernames);
            default:
                throw new IllegalArgumentException(
                        "Unknown wordlist '" + name + "'. Use list_wordlists. Known: "
                                + PASSWORDS_TOP100 + ", " + PASSWORDS_TOP250 + ", "
                                + PASSWORDS_TOP500 + ", " + USERNAMES_COMMON + ".");
        }
    }

    private static Map<String, Object> entry(String name, String description, int size) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        m.put("size", size);
        m.put("description", description);
        return m;
    }

    private static List<String> slice(List<String> all, int n) {
        if (all.isEmpty()) {
            return Collections.emptyList();
        }
        return new ArrayList<>(all.subList(0, Math.min(n, all.size())));
    }

    private static void ensureLoaded() {
        if (passwords != null && usernames != null) {
            return;
        }
        synchronized (Wordlists.class) {
            if (passwords == null) {
                passwords = read("/wordlists/passwords.txt");
            }
            if (usernames == null) {
                usernames = read("/wordlists/usernames.txt");
            }
        }
    }

    private static List<String> read(String resource) {
        List<String> out = new ArrayList<>();
        InputStream in = Wordlists.class.getResourceAsStream(resource);
        if (in == null) {
            return out;
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    out.add(line);
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }
}
