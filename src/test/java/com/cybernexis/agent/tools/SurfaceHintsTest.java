package com.cybernexis.agent.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SurfaceHintsTest {

    @Test
    void graphqlPathOutranksSearchParams() {
        SurfaceHints.Acc acc = new SurfaceHints.Acc();
        SurfaceHints.considerUrl(acc, "POST", "https://app.example/graphql", "sitemap");
        SurfaceHints.considerUrl(acc, "GET", "https://app.example/search?q=test", "sitemap");
        SurfaceHints.Hit top = acc.report().top();
        assertEquals("GraphQL", top.playbook);
        assertTrue(acc.report().strongEnough());
    }

    @Test
    void jwtFromAuthorizationHeader() {
        SurfaceHints.Acc acc = new SurfaceHints.Acc();
        SurfaceHints.considerHttp(acc,
                "GET /api/me HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n{}",
                "this request");
        assertEquals("JWT", acc.report().top().playbook);
        assertTrue(acc.report().strongEnough());
    }

    @Test
    void scannerSqlIssueIsStrongSqli() {
        SurfaceHints.Acc acc = new SurfaceHints.Acc();
        SurfaceHints.considerIssueName(acc, "SQL injection", "https://app.example/items?id=1");
        assertEquals("SQLi", acc.report().top().playbook);
        assertEquals(50, acc.report().top().score);
    }

    @Test
    void webhookParamLooksLikeSsrf() {
        SurfaceHints.Acc acc = new SurfaceHints.Acc();
        SurfaceHints.considerUrl(acc, "POST", "https://app.example/hooks?url=http://internal", "sitemap");
        assertEquals("SSRF", acc.report().top().playbook);
        assertTrue(acc.report().strongEnough());
    }

    @Test
    void objectPathLooksLikeIdor() {
        SurfaceHints.Acc acc = new SurfaceHints.Acc();
        SurfaceHints.considerUrl(acc, "GET", "https://app.example/users/42/orders/15", "sitemap");
        assertEquals("IDOR / BOLA", acc.report().top().playbook);
        assertTrue(acc.report().strongEnough());
    }

    @Test
    void loneSearchQueryIsTooWeakToAutoAttach() {
        SurfaceHints.Acc acc = new SurfaceHints.Acc();
        SurfaceHints.considerUrl(acc, "GET", "https://app.example/search?q=hello", "sitemap");
        assertFalse(acc.report().strongEnough());
    }

    @Test
    void oauthAuthorizePath() {
        SurfaceHints.Acc acc = new SurfaceHints.Acc();
        SurfaceHints.considerUrl(acc, "GET",
                "https://app.example/oauth/authorize?client_id=abc&redirect_uri=https://app.example/cb",
                "sitemap");
        assertEquals("OAuth / OIDC", acc.report().top().playbook);
    }

    @Test
    void promptBlockListsStrongestFirst() {
        SurfaceHints.Acc acc = new SurfaceHints.Acc();
        SurfaceHints.considerIssueName(acc, "SQL injection", "https://x/a");
        SurfaceHints.considerUrl(acc, "GET", "https://x/graphql", "sitemap");
        String block = acc.report().promptBlock();
        assertTrue(block.contains("SQLi"));
        assertTrue(block.contains("GraphQL"));
        assertTrue(block.indexOf("SQLi") < block.indexOf("GraphQL"));
    }
}
