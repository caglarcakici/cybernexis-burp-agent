/*
 * Tiny builder for JSON-schema "parameters" objects used by the OpenAI-compatible
 * tools array. Only the subset the model needs (object/array/string/integer/boolean).
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Schema {

    private final Map<String, Object> properties = new LinkedHashMap<>();
    private final List<String> required = new ArrayList<>();

    private Schema() {
    }

    public static Schema object() {
        return new Schema();
    }

    public Schema prop(String name, String type, String description) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("type", type);
        if (description != null) {
            p.put("description", description);
        }
        properties.put(name, p);
        return this;
    }

    public Schema arrayProp(String name, String itemType, String description) {
        Map<String, Object> items = new LinkedHashMap<>();
        items.put("type", itemType);
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("type", "array");
        p.put("items", items);
        if (description != null) {
            p.put("description", description);
        }
        properties.put(name, p);
        return this;
    }

    public Schema require(String... names) {
        for (String n : names) {
            required.add(n);
        }
        return this;
    }

    public Map<String, Object> build() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", "object");
        m.put("properties", properties);
        if (!required.isEmpty()) {
            m.put("required", required);
        }
        return m;
    }
}
