/*
 * User-visible product name. Keep the suite tab short; use PRODUCT in the
 * Extensions list, docs, and logs.
 */
package com.cybernexis.agent;

public final class Branding {

    /** Suite tab label — must stay short (same row as Proxy / Discover). */
    public static final String TAB = "Cybernexis";

    /** Full product name (Extensions list, README, logs). */
    public static final String PRODUCT = "Cybernexis Agent";

    /** Chat role, approval prompts, short UI labels. */
    public static final String SHORT = "Cybernexis";

    public static final String CONTEXT_MENU = "Send to Cybernexis";

    private Branding() {
    }

    public static String allowAction(String toolLabel) {
        return "Allow " + SHORT + " to " + toolLabel + "?";
    }
}
