/*
 * One chat "task": its own agent conversation plus display metadata for the
 * TASKS sidebar (title and running counts). The heavy UI lives in SessionPanel.
 */
package com.cybernexis.agent.ui;

public class ChatSession {

    public final String id;
    public String title;
    public int requestCount;
    public int toolCallCount;

    public final SessionPanel panel;

    public ChatSession(String id, String title, SessionPanel panel) {
        this.id = id;
        this.title = title;
        this.panel = panel;
    }
}
