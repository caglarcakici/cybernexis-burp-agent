/*
 * Builds the system message each turn: the static contract plus a live catalog
 * derived from the registry and a compact snapshot of Burp's current state.
 */
package com.cybernexis.agent.loop;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.cybernexis.agent.tools.ToolContext;
import com.cybernexis.agent.tools.ToolDescriptor;
import com.cybernexis.agent.tools.ToolRegistry;

public class PromptBuilder {

    private static final int MAX_SITEMAP = 40;
    private static final int MAX_SCOPE = 20;

    private final ToolRegistry registry;

    public PromptBuilder(ToolRegistry registry) {
        this.registry = registry;
    }

    public String buildSystemMessage(ToolContext ctx, int maxSteps) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are a senior security engineer driving Burp Suite through a set of tools. ")
          .append("Your goal is to answer the user's request about the current target, scope, and test state.\n\n");

        sb.append("RESPONSE CONTRACT\n")
          .append("Every turn you MUST respond with a SINGLE JSON object and NOTHING else. ")
          .append("No prose outside the JSON. No markdown fences.\n")
          .append("Tool call:  {\"thought\":\"<= 2 sentences\",\"tool\":\"<exact tool name>\",\"args\":{...}}\n")
          .append("Final answer: {\"thought\":\"<= 2 sentences\",\"tool\":null,\"args\":null,\"answer\":\"<markdown>\"}\n\n");

        sb.append("RULES\n")
          .append("1. One tool call per turn.\n")
          .append("2. Prefer read-only tools first. Use action tools only when the user's intent is clearly an action.\n")
          .append("3. If a tool call fails, the error is returned to you; retry with corrected args, pick another tool, or answer with what you know.\n")
          .append("4. Maximum ").append(maxSteps).append(" tool calls per user request. If not answered by then, answer with what you have.\n")
          .append("5. For security findings, structure the answer as: ## Finding / ## Evidence / ## Recommendation.\n")
          .append("6. Use EXACTLY the tool names from the catalog. Do NOT invent tool names. If the catalog lacks what you need, answer with tool=null and explain.\n")
          .append("7. Keep \"thought\" short and concrete.\n")
          .append("8. For login brute-force / password spray / credential stuffing, call brute_force with ")
          .append("wordlist=passwords-top250 (or top100/top500). Put {{pass}} in the password field via edits. ")
          .append("NEVER paste a password list into run_custom_script or fuzz_request payloads — the wordlist lives inside the tool.\n")
          .append("9. If this task has a FOCUS HOST, stay on that host only (www. is the same host). ")
          .append("Do not inspect other in-scope hosts, sibling subdomains, or leftover targets from other tasks ")
          .append("unless the user names them. list_sitemap / list_issues / inspect_scope are already filtered to the focus.\n")
          .append("10. For CSRF / session / nonce chaining: inspect or send the login page, then extract_from_response ")
          .append("(preset=csrf or a regex) into a name such as csrf, then put {{csrf}} in the next send_request or ")
          .append("brute_force body/header. {{pass}} and {{user}} stay reserved for brute_force payloads.\n")
          .append("11. TARGET MEMORY is durable per host across tasks. After you learn login_path, csrf_field, ")
          .append("session_cookie, tech, or an interesting endpoint, call remember. scan_tokens on a stored message ")
          .append("fills the Token Map (JWT/UUID/API key/CSRF locations). Do not rediscover facts already listed ")
          .append("under TARGET MEMORY. Token VALUES expire — re-extract with extract_from_response before sending.\n\n");

        sb.append("TOOL CATALOG (use these names EXACTLY)\n");
        List<ToolDescriptor> readonly = new ArrayList<>();
        List<ToolDescriptor> actions = new ArrayList<>();
        for (ToolDescriptor d : registry.all()) {
            (d.action ? actions : readonly).add(d);
        }
        sb.append("Read-only tools:\n");
        for (ToolDescriptor d : readonly) {
            sb.append("- ").append(d.name).append(": ").append(d.description).append('\n');
        }
        sb.append("Action tools (may send traffic or mutate Burp state):\n");
        for (ToolDescriptor d : actions) {
            sb.append("- ").append(d.name).append(": ").append(d.description).append('\n');
        }

        sb.append('\n').append(buildContext(ctx)).append('\n');
        sb.append(fewShot());
        return sb.toString();
    }

    private String buildContext(ToolContext ctx) {
        StringBuilder sb = new StringBuilder();
        sb.append("CURRENT STATE\n");
        String focus = ctx.focusHost();
        if (focus != null) {
            sb.append("- TASK FOCUS HOST: ").append(focus)
              .append(" (www. included). Ignore other hosts.\n");
        }

        List<HttpRequestResponse> sitemap;
        try {
            sitemap = ctx.api.siteMap().requestResponses();
        } catch (RuntimeException e) {
            sitemap = new ArrayList<>();
        }

        Set<String> inScope = new LinkedHashSet<>();
        int focusedSitemap = 0;
        for (HttpRequestResponse hrr : sitemap) {
            try {
                String url = hrr.request().url();
                if (focus != null && !com.cybernexis.agent.tools.Focus.urlMatches(url, focus)) {
                    continue;
                }
                focusedSitemap++;
                if (inScope.size() < MAX_SCOPE && ctx.api.scope().isInScope(url)) {
                    inScope.add(originOf(url));
                }
            } catch (RuntimeException ignored) {
            }
        }
        if (focus == null) {
            sb.append("- In-scope origins (derived from sitemap, first ").append(MAX_SCOPE).append("): ")
              .append(inScope.isEmpty() ? "none detected" : String.join(", ", inScope)).append('\n');
        } else {
            sb.append("- Focus origins in sitemap: ")
              .append(inScope.isEmpty() ? "none yet (browse the host or add it to scope)" : String.join(", ", inScope))
              .append('\n');
        }

        sb.append("- Sitemap items").append(focus != null ? " on focus host" : "").append(": ").append(focusedSitemap);
        if (focusedSitemap > 0) {
            sb.append(" (sample):\n");
            int shown = 0;
            for (HttpRequestResponse hrr : sitemap) {
                if (shown >= MAX_SITEMAP) {
                    break;
                }
                try {
                    String method = hrr.request().method();
                    String url = hrr.request().url();
                    if (focus != null && !com.cybernexis.agent.tools.Focus.urlMatches(url, focus)) {
                        continue;
                    }
                    String status = hrr.hasResponse() ? String.valueOf(hrr.response().statusCode()) : "-";
                    sb.append("    ").append(method).append(' ').append(url).append("  [").append(status).append("]\n");
                    shown++;
                } catch (RuntimeException ignored) {
                }
            }
        } else {
            sb.append('\n');
        }

        int issueCount = 0;
        try {
            for (AuditIssue issue : ctx.api.siteMap().issues()) {
                if (focus != null && !com.cybernexis.agent.tools.Focus.urlMatches(issue.baseUrl(), focus)) {
                    continue;
                }
                issueCount++;
            }
        } catch (RuntimeException ignored) {
        }
        sb.append("- Open issues").append(focus != null ? " on focus host" : "").append(": ").append(issueCount).append('\n');
        sb.append("- Scan tasks started this session: ").append(ctx.scanTasks().size()).append('\n');
        sb.append("- Collaborator client: ").append(ctx.hasCollaborator() ? "created" : "not yet created").append('\n');
        java.util.Map<String, String> stored = ctx.vars().snapshot();
        if (stored.isEmpty()) {
            sb.append("- Task variables: none. extract_from_response / set_variable to create {{name}} placeholders.\n");
        } else {
            sb.append("- Task variables:\n");
            for (java.util.Map.Entry<String, String> e : stored.entrySet()) {
                sb.append("    {{").append(e.getKey()).append("}} = ")
                  .append(com.cybernexis.agent.tools.Tools.truncate(e.getValue(), 80)).append('\n');
            }
        }
        sb.append(ctx.memory().promptBlock(focus));
        return sb.toString();
    }

    private static String originOf(String url) {
        try {
            java.net.URI u = java.net.URI.create(url);
            String scheme = u.getScheme();
            String host = u.getHost();
            int port = u.getPort();
            StringBuilder o = new StringBuilder();
            o.append(scheme).append("://").append(host);
            if (port > 0) {
                o.append(':').append(port);
            }
            return o.toString();
        } catch (RuntimeException e) {
            return url;
        }
    }

    private String fewShot() {
        return "EXAMPLES\n"
                + "user: What's in scope right now?\n"
                + "assistant: {\"thought\":\"List the current scope.\",\"tool\":\"inspect_scope\",\"args\":{}}\n"
                + "user: Send request 42 to the repeater.\n"
                + "assistant: {\"thought\":\"Stage request 42 in Repeater.\",\"tool\":\"send_to\",\"args\":{\"request_ids\":[42],\"destination\":\"repeater\"}}\n"
                + "user: Write me a security test plan.\n"
                + "assistant: {\"thought\":\"No tools needed.\",\"tool\":null,\"args\":null,\"answer\":\"# Security Test Plan\\n...\"}\n"
                + "user: Brute force this login with 250 passwords.\n"
                + "assistant: {\"thought\":\"Use brute_force with the built-in wordlist; do not emit passwords.\","
                + "\"tool\":\"brute_force\",\"args\":{\"url\":\"https://target/api/Auth/login\",\"method\":\"POST\","
                + "\"edits\":[{\"header\":\"Content-Type\",\"value\":\"application/json\"},"
                + "{\"body\":\"{\\\"username\\\":\\\"admin\\\",\\\"password\\\":\\\"{{pass}}\\\"}\"}],"
                + "\"wordlist\":\"passwords-top250\",\"username\":\"admin\"}}\n"
                + "user: Grab the CSRF token from message 10 and POST login.\n"
                + "assistant: {\"thought\":\"Extract the antiforgery token first.\",\"tool\":\"extract_from_response\","
                + "\"args\":{\"message_id\":10,\"name\":\"csrf\",\"preset\":\"csrf\"}}\n"
                + "user: Remember the login path and scan message 10 for tokens.\n"
                + "assistant: {\"thought\":\"Persist login_path then map tokens on the login response.\","
                + "\"tool\":\"remember\",\"args\":{\"key\":\"login_path\",\"value\":\"/Auth/SignIn\"}}\n";
    }
}
