package com.cybernexis.agent.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PlaybooksTest {

    @Test
    void catalogHasTwelvePlaybooks() {
        assertEquals(12, Playbooks.all().size());
        for (TaskTemplates.Template t : Playbooks.all()) {
            assertEquals(Playbooks.GROUP, t.group);
            assertTrue(t.instructions.contains("PLAYBOOK: " + t.name), t.name);
            assertTrue(t.instructions.contains("PLAYBOOK RULES"), t.name);
        }
    }

    @Test
    void matchPicksSpecificClasses() {
        assertEquals("IDOR / BOLA", Playbooks.match("Test IDOR on /users/{id}").name);
        assertEquals("JWT", Playbooks.match("Inspect the JWT in the Authorization header").name);
        assertEquals("SSRF", Playbooks.match("Check this webhook parameter for SSRF").name);
        assertEquals("GraphQL", Playbooks.match("POST https://app.example/graphql").name);
        assertEquals("OAuth / OIDC", Playbooks.match("Map the OAuth authorize redirect_uri").name);
        assertEquals("SQLi", Playbooks.match("Look for SQL injection on the search box").name);
        assertEquals("XSS", Playbooks.match("Any reflected XSS in q=").name);
        assertEquals("Reporting", Playbooks.match("Write a report of confirmed issues").name);
        assertEquals("Fast checking", Playbooks.match("Run a fast check / first pass").name);
    }

    @Test
    void matchPrefersGraphQLOverGenericIdorWhenBothPresent() {
        assertEquals("GraphQL", Playbooks.match("GraphQL IDOR on node(id)").name);
    }

    @Test
    void inspectOnlyQuestionsDoNotCountAsTestIntent() {
        assertFalse(Playbooks.looksLikeTestIntent("What's in scope right now?"));
        assertFalse(Playbooks.looksLikeTestIntent("list the sitemap"));
        assertTrue(Playbooks.looksLikeTestIntent("Analyze this host for vulnerabilities"));
        assertTrue(Playbooks.looksLikeTestIntent("https://shop.example/ test this"));
        assertNull(Playbooks.match("What's in scope right now?"));
        assertNull(Playbooks.match(""));
        assertNull(Playbooks.match(null));
    }

    @Test
    void alreadyAppliedDetectsMarker() {
        TaskTemplates.Template jwt = Playbooks.byName("JWT");
        assertNotNull(jwt);
        assertTrue(Playbooks.alreadyApplied(jwt.instructions, jwt));
        assertFalse(Playbooks.alreadyApplied("Act as a web tester", jwt));
        assertTrue(Playbooks.isPlaybook("JWT"));
        assertFalse(Playbooks.isPlaybook("Blank"));
    }
}
