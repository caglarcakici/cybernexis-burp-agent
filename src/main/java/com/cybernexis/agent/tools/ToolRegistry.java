/*
 * Ordered registry of tools available to the agent. Preserves catalog order for
 * a stable system prompt and provides nearest-name matching for typo recovery.
 */
package com.cybernexis.agent.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.cybernexis.agent.util.Levenshtein;

public class ToolRegistry {

    private final Map<String, ToolDescriptor> byName = new LinkedHashMap<>();

    public void register(ToolDescriptor descriptor) {
        byName.put(descriptor.name, descriptor);
    }

    public ToolDescriptor get(String name) {
        return name == null ? null : byName.get(name);
    }

    public boolean contains(String name) {
        return name != null && byName.containsKey(name);
    }

    public List<ToolDescriptor> all() {
        return new ArrayList<>(byName.values());
    }

    public List<String> names() {
        return new ArrayList<>(byName.keySet());
    }

    /** Closest tool name within an edit-distance threshold, or null. */
    public String suggest(String name) {
        if (name == null) {
            return null;
        }
        String best = null;
        int bestDist = Integer.MAX_VALUE;
        for (String candidate : byName.keySet()) {
            int d = Levenshtein.distance(name, candidate);
            if (d < bestDist) {
                bestDist = d;
                best = candidate;
            }
        }
        int threshold = Math.max(2, name.length() / 3);
        return bestDist <= threshold ? best : null;
    }
}
