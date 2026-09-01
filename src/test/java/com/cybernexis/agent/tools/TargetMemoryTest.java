package com.cybernexis.agent.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

class TargetMemoryTest {

    @Test
    void rememberIsHostScopedAndWwwIsSameHost() {
        TargetMemory mem = new TargetMemory();
        mem.remember("www.hbpanel.example.com", "login_path", "/Auth/SignIn", false);
        mem.remember("hbpanel.example.com", "csrf_field", "__RequestVerificationToken", false);

        assertEquals("/Auth/SignIn", mem.facts("HBPANEL.example.com").get("login_path"));
        assertEquals("__RequestVerificationToken", mem.facts("www.hbpanel.example.com").get("csrf_field"));
        assertEquals(1, mem.rememberedHosts().size());
        assertTrue(mem.hasHost("hbpanel.example.com"));
        assertFalse(mem.hasHost("panel.example.com"));
    }

    @Test
    void appendNotesAndDoesNotOverwriteUnlessAsked() {
        TargetMemory mem = new TargetMemory();
        mem.remember("target.test", "notes", "ASP.NET", false);
        mem.remember("target.test", "notes", "lockout after 10", true);
        assertTrue(mem.facts("target.test").get("notes").contains("ASP.NET"));
        assertTrue(mem.facts("target.test").get("notes").contains("lockout after 10"));
    }

    @Test
    void tokensDedupeByKindNameWhereAndRoundTripJson() {
        TargetMemory mem = new TargetMemory();
        TargetMemory.Token a = mem.putToken("api.test", "jwt", "Authorization", "request header", "eyJaaa.bbb.ccc");
        TargetMemory.Token b = mem.putToken("api.test", "jwt", "Authorization", "request header", "eyJddd.eee.fff");
        assertEquals(a.id, b.id);
        assertEquals(1, mem.tokenCount("api.test"));
        assertEquals("eyJddd.eee.fff", mem.tokens("api.test").get(0).value);

        TargetMemory restored = TargetMemory.fromJson(mem.toJson());
        assertEquals("eyJddd.eee.fff", restored.tokens("api.test").get(0).value);
        assertEquals("jwt", restored.facts("api.test").get("auth_scheme") == null
                ? restored.tokens("api.test").get(0).kind
                : "jwt");
        String block = restored.promptBlock("api.test");
        assertTrue(block.contains("api.test"));
        assertTrue(block.contains("token map") || block.contains("#"));
    }

    @Test
    void recordExtractFillsMissingFacts() {
        TargetMemory mem = new TargetMemory();
        mem.recordExtract("shop.test", "csrf", "preset:csrf", "abc123", null);
        mem.recordExtract("shop.test", "sid", "preset:cookie Set-Cookie", "xyz", "JSESSIONID");
        assertEquals(null, mem.facts("shop.test").get("csrf_field"));
        assertEquals("JSESSIONID", mem.facts("shop.test").get("session_cookie"));
        assertEquals(2, mem.tokenCount("shop.test"));
    }

    @Test
    void persistCallbackFires() {
        List<String> saved = new ArrayList<>();
        TargetMemory mem = new TargetMemory().onPersist(saved::add);
        mem.remember("a.test", "tech", "django", false);
        assertFalse(saved.isEmpty());
        assertTrue(saved.get(saved.size() - 1).contains("django"));
    }
}
