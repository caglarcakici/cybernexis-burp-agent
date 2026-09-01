/*
 * Registers the Cybernexis Agent tool catalog in a stable order.
 */
package com.cybernexis.agent.tools;

public final class BurpTools {

    private BurpTools() {
    }

    public static ToolRegistry buildRegistry() {
        ToolRegistry registry = new ToolRegistry();
        // Phase 1 — read-only
        ScopeTools.register(registry);        // inspect_scope (+ scope actions below)
        SitemapTools.register(registry);
        IssueTools.register(registry);
        HttpMessageTools.register(registry);
        VariableTools.register(registry);
        MemoryTools.register(registry);
        OrganizerTools.register(registry);
        ScannerTools.register(registry);
        FuzzTools.register(registry);
        BruteForceTools.register(registry);
        CollaboratorTools.register(registry);
        // Phase 3 — advanced (scripts, Bambda/BCheck, API query, utilities, compare)
        BCheckTools.register(registry);
        ScriptTools.register(registry);
        ApiQueryTools.register(registry);
        CompareTools.register(registry);
        UtilTools.register(registry);
        return registry;
    }
}
