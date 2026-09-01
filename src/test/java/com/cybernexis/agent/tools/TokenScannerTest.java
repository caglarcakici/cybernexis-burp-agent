package com.cybernexis.agent.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class TokenScannerTest {

    @Test
    void findsJwtCsrfSessionCookieAndLoginPath() {
        String req = "POST /Auth/SignIn HTTP/1.1\r\n"
                + "Host: hbpanel.example.com\r\n"
                + "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc\r\n"
                + "\r\n";
        String res = "HTTP/1.1 200 OK\r\n"
                + "Set-Cookie: JSESSIONID=abc123def456; HttpOnly\r\n"
                + "Set-Cookie: theme=dark; Path=/\r\n"
                + "\r\n"
                + "<input name=\"__RequestVerificationToken\" value=\"csrf-live-value\" />";

        List<TokenScanner.Hit> hits = TokenScanner.scan(req, res);

        assertTrue(hits.stream().anyMatch(h -> "login_path".equals(h.factKey)
                && "/Auth/SignIn".equals(h.factValue)));
        assertTrue(hits.stream().anyMatch(h -> "jwt".equals(h.kind)));
        assertTrue(hits.stream().anyMatch(h -> "JSESSIONID".equals(h.name) && "cookie".equals(h.kind)));
        assertTrue(hits.stream().noneMatch(h -> "theme".equalsIgnoreCase(h.name)));
        assertTrue(hits.stream().anyMatch(h -> "__RequestVerificationToken".equals(h.name)
                && "csrf".equals(h.kind)));
    }

    @Test
    void findsPathUuidAndSkipsNoiseCookies() {
        String req = "GET /api/users/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1\r\n"
                + "Host: api.example.com\r\n\r\n";
        List<TokenScanner.Hit> hits = TokenScanner.scan(req, "");
        assertEquals(1, hits.stream().filter(h -> "uuid".equals(h.kind)).count());
        assertTrue(hits.stream().anyMatch(h -> h.value.startsWith("550e8400")));
    }
}
