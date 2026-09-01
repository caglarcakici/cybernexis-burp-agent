/*
 * The chat tab shell: a TASKS sidebar listing sessions on the left and the
 * active session's SessionPanel on the right (CardLayout). Owns session
 * lifecycle (create / switch / delete) and refreshes sidebar cards on activity.
 */
package com.cybernexis.agent.ui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import com.cybernexis.agent.Config;
import com.cybernexis.agent.ollama.OllamaClient;
import com.cybernexis.agent.json.Json;
import com.cybernexis.agent.tools.ToolContext;
import com.cybernexis.agent.tools.ToolRegistry;

import burp.api.montoya.persistence.Preferences;

public class ChatView extends JPanel implements SessionPanel.Host {

    private static final String SESSIONS_KEY = "com.cybernexis.agent.sessions";

    private final Config config;
    private final OllamaClient client;
    private final ToolRegistry registry;
    private final ToolContext ctx;
    private final ToolActivityLog activityLog;
    private final Preferences prefs;

    private final List<ChatSession> sessions = new ArrayList<>();
    private String activeId;
    private int sessionSeq;
    private boolean restoring;

    private final JPanel center = new JPanel(new CardLayout());
    private final JPanel sidebarList = new JPanel();

    public ChatView(Config config, OllamaClient client, ToolRegistry registry,
                    ToolContext ctx, ToolActivityLog activityLog, Preferences prefs) {
        super(new BorderLayout());
        this.config = config;
        this.client = client;
        this.registry = registry;
        this.ctx = ctx;
        this.activityLog = activityLog;
        this.prefs = prefs;

        setBackground(Theme.panel());
        add(buildSidebar(), BorderLayout.WEST);
        center.setBackground(Theme.panel());
        add(center, BorderLayout.CENTER);

        loadSessions();
        if (sessions.isEmpty()) {
            newSession(null);
        }
    }

    private Component buildSidebar() {
        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setBackground(Theme.surface());
        sidebar.setPreferredSize(new Dimension(230, 100));
        sidebar.setBorder(javax.swing.BorderFactory.createMatteBorder(0, 0, 0, 1, Theme.border()));

        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        header.setBorder(Theme.pad(12, 14, 8, 10));
        JLabel title = new JLabel("TASKS");
        title.setFont(Theme.bold(11f));
        title.setForeground(Theme.mutedText());
        JButton add = new JButton("+");
        add.setToolTipText("New task");
        add.setFont(Theme.bold(15f));
        add.setMargin(new java.awt.Insets(0, 8, 0, 8));
        add.addActionListener(e -> showTemplateMenu(add));
        header.add(title, BorderLayout.WEST);
        header.add(add, BorderLayout.EAST);

        sidebarList.setLayout(new BoxLayout(sidebarList, BoxLayout.Y_AXIS));
        sidebarList.setOpaque(false);
        sidebarList.setBorder(Theme.pad(4, 8, 8, 8));
        JScrollPane scroll = new JScrollPane(sidebarList,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(null);
        scroll.getViewport().setBackground(Theme.surface());
        scroll.getVerticalScrollBar().setUnitIncrement(16);

        sidebar.add(header, BorderLayout.NORTH);
        sidebar.add(scroll, BorderLayout.CENTER);
        return sidebar;
    }

    private void showTemplateMenu(Component anchor) {
        javax.swing.JPopupMenu menu = new javax.swing.JPopupMenu();
        for (TaskTemplates.Template t : TaskTemplates.defaults()) {
            javax.swing.JMenuItem item = new javax.swing.JMenuItem(t.name);
            item.addActionListener(e -> newSession(t));
            menu.add(item);
        }
        menu.show(anchor, 0, anchor.getHeight());
    }

    private ChatSession newSession(TaskTemplates.Template template) {
        String id = "session-" + (++sessionSeq);
        SessionPanel panel = new SessionPanel(config, client, registry, ctx, activityLog, this);
        String title = (template != null && !"Blank".equals(template.name)) ? template.name : "New task";
        ChatSession session = new ChatSession(id, title, panel);
        panel.setSession(session);
        if (template != null) {
            panel.applyTemplate(template.name, template.instructions);
        }
        sessions.add(session);
        center.add(panel, id);
        setActive(id);
        refreshSidebar();
        saveSessions();
        return session;
    }

    /** Create a session seeded from a right-clicked HTTP message ("Send to Cybernexis"). */
    public void newSessionForRequest(burp.api.montoya.http.message.HttpRequestResponse hrr) {
        ChatSession session = newSession(null);
        session.title = "Request analysis";
        session.panel.seedWithRequest(hrr);
        refreshSidebar();
        saveSessions();
    }

    private void setActive(String id) {
        activeId = id;
        ((CardLayout) center.getLayout()).show(center, id);
        refreshSidebar();
    }

    private void deleteSession(String id) {
        ChatSession found = null;
        for (ChatSession s : sessions) {
            if (s.id.equals(id)) {
                found = s;
                break;
            }
        }
        if (found == null) {
            return;
        }
        sessions.remove(found);
        center.remove(found.panel);
        if (sessions.isEmpty()) {
            newSession(null);
            return;
        }
        if (id.equals(activeId)) {
            setActive(sessions.get(sessions.size() - 1).id);
        } else {
            refreshSidebar();
        }
        saveSessions();
    }

    private void refreshSidebar() {
        sidebarList.removeAll();
        for (ChatSession s : sessions) {
            sidebarList.add(buildSessionCard(s));
            sidebarList.add(Box.createVerticalStrut(6));
        }
        sidebarList.revalidate();
        sidebarList.repaint();
    }

    private Component buildSessionCard(ChatSession s) {
        boolean active = s.id.equals(activeId);
        RoundedPanel card = new RoundedPanel(new BorderLayout(6, 0));
        card.setArc(10);
        card.setFill(active ? Theme.blend(Theme.surface(), Theme.accent(), 0.16) : Theme.surfaceAlt());
        card.setLine(active ? Theme.blend(Theme.border(), Theme.accent(), 0.4) : Theme.border());
        card.setBorder(Theme.pad(8, 10, 8, 8));
        card.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 58));

        JPanel texts = new JPanel();
        texts.setOpaque(false);
        texts.setLayout(new BoxLayout(texts, BoxLayout.Y_AXIS));
        JLabel title = new JLabel(ellipsize(s.title, 24));
        title.setFont(Theme.bold(12f));
        title.setForeground(Theme.text());
        title.setAlignmentX(LEFT_ALIGNMENT);
        JLabel sub = new JLabel(counts(s));
        sub.setFont(Theme.plain(10f));
        sub.setForeground(Theme.mutedText());
        sub.setAlignmentX(LEFT_ALIGNMENT);
        texts.add(title);
        texts.add(Box.createVerticalStrut(2));
        texts.add(sub);

        JButton close = new JButton("\u00d7");
        close.setToolTipText("Close task");
        close.setBorderPainted(false);
        close.setContentAreaFilled(false);
        close.setForeground(Theme.mutedText());
        close.setFont(Theme.bold(14f));
        close.setMargin(new java.awt.Insets(0, 4, 0, 4));
        close.addActionListener(e -> deleteSession(s.id));

        card.add(texts, BorderLayout.CENTER);
        card.add(close, BorderLayout.EAST);
        card.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                setActive(s.id);
            }
        });
        return card;
    }

    private static String counts(ChatSession s) {
        String r = s.requestCount + (s.requestCount == 1 ? " request" : " requests");
        String t = s.toolCallCount + (s.toolCallCount == 1 ? " tool call" : " tool calls");
        return r + " \u00b7 " + t;
    }

    private static String ellipsize(String s, int max) {
        if (s == null) {
            return "New task";
        }
        return s.length() <= max ? s : s.substring(0, max) + "\u2026";
    }

    @Override
    public void onSessionActivity(ChatSession session) {
        refreshSidebar();
        saveSessions();
    }

    // ---- Persistence --------------------------------------------------------

    private void saveSessions() {
        if (restoring || prefs == null) {
            return;
        }
        try {
            List<Object> arr = new ArrayList<>();
            for (ChatSession s : sessions) {
                java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
                m.put("id", s.id);
                m.put("title", s.title);
                m.put("requests", s.requestCount);
                m.put("tool_calls", s.toolCallCount);
                m.put("mode", s.panel.getMode().name());
                m.put("template", s.panel.getTemplateName());
                m.put("instructions", s.panel.getSystemAddendum());
                m.put("focus_host", s.panel.getFocusHost());
                m.put("variables", s.panel.snapshotVariables());
                m.put("conversation", s.panel.snapshotConversation());
                m.put("log", s.panel.getLog());
                arr.add(m);
            }
            java.util.Map<String, Object> root = new java.util.LinkedHashMap<>();
            root.put("active", activeId);
            root.put("sessions", arr);
            prefs.setString(SESSIONS_KEY, Json.write(root));
        } catch (RuntimeException ignored) {
            // Persistence is best-effort.
        }
    }

    private void loadSessions() {
        if (prefs == null) {
            return;
        }
        String json = prefs.getString(SESSIONS_KEY);
        if (json == null || json.trim().isEmpty()) {
            return;
        }
        restoring = true;
        try {
            java.util.Map<String, Object> root = Json.parseObject(json);
            Object listObj = root.get("sessions");
            if (!(listObj instanceof List)) {
                return;
            }
            String savedActive = str(root.get("active"));
            for (Object o : (List<?>) listObj) {
                if (!(o instanceof java.util.Map)) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                java.util.Map<String, Object> m = (java.util.Map<String, Object>) o;
                String id = "session-" + (++sessionSeq);
                SessionPanel panel = new SessionPanel(config, client, registry, ctx, activityLog, this);
                ChatSession session = new ChatSession(id, str(m.getOrDefault("title", "Task")), panel);
                session.requestCount = intOf(m.get("requests"));
                session.toolCallCount = intOf(m.get("tool_calls"));
                panel.setSession(session);
                panel.restore(parseMode(str(m.get("mode"))), str(m.get("template")),
                        str(m.get("instructions")), listOfMaps(m.get("conversation")), listOfMaps(m.get("log")),
                        str(m.get("focus_host")), stringMap(m.get("variables")));
                sessions.add(session);
                center.add(panel, id);
                if (savedActive != null && savedActive.equals(str(m.get("id")))) {
                    activeId = id;
                }
            }
            if (activeId == null && !sessions.isEmpty()) {
                activeId = sessions.get(sessions.size() - 1).id;
            }
            if (activeId != null) {
                ((CardLayout) center.getLayout()).show(center, activeId);
            }
        } catch (RuntimeException ignored) {
            // Corrupt state: start fresh.
        } finally {
            restoring = false;
            refreshSidebar();
        }
    }

    private static SessionPanel.Mode parseMode(String s) {
        if (s == null) {
            return SessionPanel.Mode.SMART;
        }
        try {
            return SessionPanel.Mode.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return SessionPanel.Mode.SMART;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<java.util.Map<String, Object>> listOfMaps(Object o) {
        List<java.util.Map<String, Object>> out = new ArrayList<>();
        if (o instanceof List) {
            for (Object e : (List<?>) o) {
                if (e instanceof java.util.Map) {
                    out.add((java.util.Map<String, Object>) e);
                }
            }
        }
        return out;
    }

    private static java.util.Map<String, String> stringMap(Object o) {
        java.util.Map<String, String> out = new java.util.LinkedHashMap<>();
        if (o instanceof java.util.Map) {
            for (java.util.Map.Entry<?, ?> e : ((java.util.Map<?, ?>) o).entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    out.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
                }
            }
        }
        return out;
    }

    private static int intOf(Object o) {
        return o instanceof Number ? ((Number) o).intValue() : 0;
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }
}
