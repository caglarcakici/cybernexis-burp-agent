/*
 * Built-in task templates: a name plus system-prompt instructions that steer a
 * session toward a particular kind of engagement. Selecting one when creating a
 * task seeds the agent's system prompt. Playbooks (vuln-class checklists) live
 * in Playbooks and appear under a submenu.
 */
package com.cybernexis.agent.ui;

import java.util.ArrayList;
import java.util.List;

public final class TaskTemplates {

    public static final String GROUP_ENGAGEMENT = "Engagement";

    public static final class Template {
        public final String name;
        public final String group;
        public final String instructions;
        public final String[] keywords;

        public Template(String name, String instructions) {
            this(name, GROUP_ENGAGEMENT, instructions, new String[0]);
        }

        public Template(String name, String group, String instructions, String[] keywords) {
            this.name = name;
            this.group = group == null ? GROUP_ENGAGEMENT : group;
            this.instructions = instructions == null ? "" : instructions;
            this.keywords = keywords == null ? new String[0] : keywords;
        }

        public boolean isPlaybook() {
            return Playbooks.GROUP.equals(group);
        }
    }

    private TaskTemplates() {
    }

    public static List<Template> engagements() {
        List<Template> list = new ArrayList<>();
        list.add(new Template("Blank", ""));
        list.add(new Template("Web App Vulnerability Testing",
                "Act as a web application penetration tester. Map the application, identify interesting "
                        + "inputs and endpoints, then test likely vulnerabilities (injection, access control, "
                        + "auth, SSRF, IDOR). Start with a low-noise crawl and passive review before active "
                        + "testing. Confirm any finding with a minimal proof-of-concept and report the exact "
                        + "request, the response evidence, and where the issue appears in Burp. Stay strictly "
                        + "within the in-scope hosts and avoid destructive actions; ask before anything high-impact."));
        list.add(new Template("API Security Testing",
                "Act as an API security tester. Enumerate endpoints and parameters, inspect authentication and "
                        + "authorization (tokens, scopes, roles), and probe for BOLA/IDOR, mass assignment, "
                        + "excessive data exposure, and injection. Prefer send_request/run_custom_script for "
                        + "precise header and body control. Document each issue with the request/response pair."));
        list.add(new Template("Recon / Attack Surface Mapping",
                "Perform read-only reconnaissance only. Enumerate scope, sitemap, endpoints, technologies, and "
                        + "notable responses. Do NOT send new requests, scan, or mutate Burp state. Summarize the "
                        + "attack surface and suggest where a tester should focus next."));
        list.add(new Template("Triage Existing Findings",
                "Review the audit issues already present in Burp. Group them by severity and type, remove likely "
                        + "false positives with justification, and produce a prioritized remediation list with "
                        + "concrete evidence drawn from the stored HTTP messages."));
        return list;
    }

    /** Engagement templates plus playbooks, Blank first. */
    public static List<Template> defaults() {
        List<Template> list = new ArrayList<>(engagements());
        list.addAll(Playbooks.all());
        return list;
    }
}
