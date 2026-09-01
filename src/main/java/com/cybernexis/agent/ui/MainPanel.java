/*
 * The single suite tab: Chat, Settings, and Activity Log.
 */
package com.cybernexis.agent.ui;

import java.awt.BorderLayout;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;

public class MainPanel extends JPanel {

    public MainPanel(ChatView chatView, ConfigPanel configPanel, ToolActivityLog activityLog) {
        super(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Chat", chatView);
        tabs.addTab("Settings", configPanel);
        tabs.addTab("Activity Log", activityLog);
        add(tabs, BorderLayout.CENTER);
    }
}
