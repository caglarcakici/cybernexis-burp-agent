/*
 * Loads and saves Config to Burp's persistent preference store, keyed under a
 * single JSON string so schema changes don't require new preference keys.
 */
package com.cybernexis.agent;

import burp.api.montoya.persistence.Preferences;

public class ConfigStore {

    private static final String KEY = "com.cybernexis.agent.config";

    private final Preferences prefs;

    public ConfigStore(Preferences prefs) {
        this.prefs = prefs;
    }

    public Config load() {
        String json = prefs.getString(KEY);
        return Config.fromJson(json);
    }

    public void save(Config config) {
        prefs.setString(KEY, config.toJson());
    }
}
