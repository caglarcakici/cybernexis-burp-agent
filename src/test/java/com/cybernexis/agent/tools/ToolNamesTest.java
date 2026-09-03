package com.cybernexis.agent.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ToolNamesTest {

    @Test
    void titlesCommonTools() {
        assertEquals("Add to Scope", ToolNames.displayName("add_to_scope"));
        assertEquals("Crawl and Audit", ToolNames.displayName("crawl_and_audit"));
        assertEquals("List Sitemap", ToolNames.displayName("list_sitemap"));
        assertEquals("List Proxy History", ToolNames.displayName("list_proxy_history"));
        assertEquals("Send Request", ToolNames.displayName("send_request"));
        assertEquals("Extract from Response", ToolNames.displayName("extract_from_response"));
        assertEquals("Inspect HTTP Message", ToolNames.displayName("inspect_http_message"));
        assertEquals("Search HTTP Messages", ToolNames.displayName("search_http_messages"));
    }
}
