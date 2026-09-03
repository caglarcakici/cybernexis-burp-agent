/*
 * The chat surface for a single session: a width-tracking transcript of message
 * bubbles / tool cards / inline approvals, plus an input row with a mode
 * selector. Implements AgentLoop.Listener and runs the agent on a worker thread.
 */
package com.cybernexis.agent.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.swing.AbstractAction;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.Scrollable;
import javax.swing.SwingUtilities;

import com.cybernexis.agent.Config;
import com.cybernexis.agent.loop.AgentLoop;
import com.cybernexis.agent.loop.ToolCall;
import com.cybernexis.agent.ollama.OllamaClient;
import com.cybernexis.agent.tools.ToolContext;
import com.cybernexis.agent.tools.ToolDescriptor;
import com.cybernexis.agent.tools.ToolNames;
import com.cybernexis.agent.tools.ToolResult;

public class SessionPanel extends JPanel implements AgentLoop.Listener {

    /** Approval policy for action tools. */
    public enum Mode {
        MANUAL("Manual \u00b7 ask every action"),
        SMART("Smart \u00b7 auto, escalate risky"),
        AUTO("Auto \u00b7 run everything");

        final String label;

        Mode(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /** Tools that Smart mode escalates to a manual prompt. */
    private static final Set<String> HIGH_IMPACT = new HashSet<>(Arrays.asList(
            "crawl_and_audit", "audit_request", "fuzz_request", "brute_force", "run_custom_script", "send_request"));

    public interface Host {
        void onSessionActivity(ChatSession session);
    }

    private final Config config;
    private final ToolContext ctx;
    private final ToolActivityLog activityLog;
    private final AgentLoop agentLoop;
    private final Host host;

    private ChatSession session;

    private final TranscriptPanel transcript = new TranscriptPanel();
    private final JScrollPane scroll = new JScrollPane(transcript);
    private final JTextArea input = new JTextArea(1, 40);
    private final JButton sendButton = new JButton("Send");
    private final JButton stopButton = new JButton("Stop");
    private final JComboBox<Mode> modeCombo = new JComboBox<>(Mode.values());
    private final JLabel statusLabel = new JLabel("Ready");
    private final JButton jumpButton = new JButton("\u2193 Jump to latest");

    private volatile OllamaClient.CancelToken cancelToken;
    private volatile Mode mode;
    private String templateName = "Blank";

    // Persisted display log (independent of the model conversation).
    private final java.util.List<Map<String, Object>> log = new java.util.ArrayList<>();

    // Transient per-turn UI references (touched on the EDT).
    private ToolCallCard currentToolCard;
    private JPanel liveThinking;
    private Component liveThinkingRow;
    private JTextArea liveThinkingText;
    private volatile ApprovalCard pendingApproval;
    private boolean stickToBottom = true;

    public SessionPanel(Config config, OllamaClient client, com.cybernexis.agent.tools.ToolRegistry registry,
                        ToolContext ctx, ToolActivityLog activityLog, Host host) {
        super(new BorderLayout());
        this.config = config;
        this.ctx = ctx;
        this.activityLog = activityLog;
        this.host = host;
        this.agentLoop = new AgentLoop(config, client, registry, ctx);
        this.mode = parseMode(config.agentMode);

        buildUi();
        addWelcome();
    }

    void setSession(ChatSession session) {
        this.session = session;
    }

    // ---- UI construction ----------------------------------------------------

    private void buildUi() {
        setBackground(Theme.panel());

        transcript.setBackground(Theme.panel());
        transcript.setBorder(Theme.pad(14, 16, 14, 16));
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        scroll.setViewportView(transcript);
        scroll.getViewport().setBackground(Theme.panel());
        scroll.getVerticalScrollBar().addAdjustmentListener(e -> {
            javax.swing.JScrollBar bar = scroll.getVerticalScrollBar();
            stickToBottom = (bar.getValue() + bar.getVisibleAmount()) >= (bar.getMaximum() - 40);
            jumpButton.setVisible(!stickToBottom);
        });
        scroll.getViewport().addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                // Width changed: recompute wrapped heights of markdown rows.
                transcript.revalidate();
            }
        });

        add(scroll, BorderLayout.CENTER);
        add(buildInputBar(), BorderLayout.SOUTH);

        modeCombo.setSelectedItem(mode);
        modeCombo.addActionListener(e -> mode = (Mode) modeCombo.getSelectedItem());

        sendButton.addActionListener(e -> onSend());
        stopButton.addActionListener(e -> onStop());
        stopButton.setEnabled(false);

        input.setLineWrap(true);
        input.setWrapStyleWord(true);
        input.setFont(Theme.plain(13f));
        input.setBorder(Theme.pad(8, 10, 8, 10));
        input.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "send");
        input.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,
                java.awt.event.InputEvent.SHIFT_DOWN_MASK), "newline");
        input.getActionMap().put("send", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                onSend();
            }
        });
        input.getActionMap().put("newline", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                input.append("\n");
            }
        });
    }

    private JComponent buildInputBar() {
        JPanel bar = new JPanel(new BorderLayout(8, 6));
        bar.setBackground(Theme.panel());
        bar.setBorder(Theme.pad(6, 12, 12, 12));

        RoundedPanel field = new RoundedPanel(new BorderLayout(8, 0));
        field.setArc(16).setFill(Theme.surface()).setLine(Theme.border());
        field.setBorder(Theme.pad(4, 6, 4, 6));
        JScrollPane inputScroll = new JScrollPane(input,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        inputScroll.setBorder(null);
        inputScroll.setOpaque(false);
        inputScroll.getViewport().setOpaque(false);
        input.setOpaque(false);
        inputScroll.setPreferredSize(new Dimension(100, 60));
        field.add(inputScroll, BorderLayout.CENTER);

        JPanel controls = new JPanel();
        controls.setOpaque(false);
        controls.setLayout(new BoxLayout(controls, BoxLayout.X_AXIS));
        controls.add(stopButton);
        controls.add(Box.createHorizontalStrut(6));
        controls.add(sendButton);
        field.add(controls, BorderLayout.EAST);

        JPanel meta = new JPanel(new BorderLayout());
        meta.setOpaque(false);
        meta.setBorder(Theme.pad(6, 2, 0, 2));
        JPanel left = new JPanel();
        left.setOpaque(false);
        left.setLayout(new BoxLayout(left, BoxLayout.X_AXIS));
        JLabel modeLabel = new JLabel("Mode:");
        modeLabel.setForeground(Theme.mutedText());
        modeLabel.setFont(Theme.plain(11f));
        modeCombo.setFont(Theme.plain(11f));
        modeCombo.setMaximumSize(new Dimension(220, 26));
        JButton exportButton = new JButton("Export\u2026");
        exportButton.setFont(Theme.plain(11f));
        exportButton.setToolTipText("Export this task as Markdown/HTML");
        exportButton.addActionListener(e -> exportReport());
        left.add(modeLabel);
        left.add(Box.createHorizontalStrut(6));
        left.add(modeCombo);
        left.add(Box.createHorizontalStrut(10));
        left.add(exportButton);

        statusLabel.setForeground(Theme.mutedText());
        statusLabel.setFont(Theme.plain(11f));
        jumpButton.setFont(Theme.plain(11f));
        jumpButton.setVisible(false);
        jumpButton.addActionListener(e -> {
            stickToBottom = true;
            autoScroll();
        });
        JPanel right = new JPanel();
        right.setOpaque(false);
        right.setLayout(new BoxLayout(right, BoxLayout.X_AXIS));
        right.add(jumpButton);
        right.add(Box.createHorizontalStrut(10));
        right.add(statusLabel);

        meta.add(left, BorderLayout.WEST);
        meta.add(right, BorderLayout.EAST);

        bar.add(field, BorderLayout.CENTER);
        bar.add(meta, BorderLayout.SOUTH);
        return bar;
    }

    private String shownFocus;

    private void addWelcome() {
        JLabel hello = new JLabel(com.cybernexis.agent.Branding.PRODUCT
                + " ready \u2014 ask about scope, sitemap, issues, or request an action.");
        hello.setForeground(Theme.mutedText());
        hello.setFont(Theme.plain(12f));
        hello.setAlignmentX(LEFT_ALIGNMENT);
        transcript.addRow(hello);
    }

    private void showFocusChip(String host) {
        if (host == null || host.equals(shownFocus)) {
            return;
        }
        shownFocus = host;
        Chip chip = new Chip("Focus \u00b7 " + host, Theme.accent(),
                Theme.blend(Theme.surface(), Theme.accent(), 0.16));
        JPanel row = new JPanel(new BorderLayout());
        row.setOpaque(false);
        row.add(chip, BorderLayout.WEST);
        transcript.addRow(row);
        showMemoryChip(host);
    }

    private void showMemoryChip(String host) {
        com.cybernexis.agent.tools.TargetMemory mem = ctx.memory();
        if (host == null || !mem.hasHost(host)) {
            return;
        }
        int facts = mem.factCount(host);
        int tokens = mem.tokenCount(host);
        Chip chip = new Chip("Memory \u00b7 " + facts + " facts \u00b7 " + tokens + " tokens",
                Theme.text(), Theme.blend(Theme.surface(), Theme.accent(), 0.12));
        JPanel row = new JPanel(new BorderLayout());
        row.setOpaque(false);
        row.add(chip, BorderLayout.WEST);
        transcript.addRow(row);
    }

    // ---- Actions ------------------------------------------------------------

    private void onSend() {
        String text = input.getText().trim();
        if (text.isEmpty() || cancelToken != null) {
            return;
        }
        input.setText("");
        addUserBubble(text);
        logRecord("user", "text", text);
        String inferred = com.cybernexis.agent.tools.Focus.inferHost(text);
        if (inferred != null) {
            agentLoop.setFocusHost(inferred);
            showFocusChip(inferred);
        }
        if (session != null) {
            session.requestCount++;
            if (session.requestCount == 1) {
                session.title = deriveTitle(text);
            }
            notifyHost();
        }
        setRunning(true);

        cancelToken = new OllamaClient.CancelToken();
        Thread worker = new Thread(() -> {
            try {
                agentLoop.runUserTurn(text, this, cancelToken);
            } catch (Exception ex) {
                onError(ex.getMessage());
            } finally {
                cancelToken = null;
                SwingUtilities.invokeLater(() -> setRunning(false));
            }
        }, "cybernexis-agent");
        worker.setDaemon(true);
        worker.start();
    }

    private void onStop() {
        OllamaClient.CancelToken t = cancelToken;
        if (t != null) {
            t.cancel();
        }
        ApprovalCard pending = pendingApproval;
        if (pending != null) {
            pending.cancel();
        }
        statusLabel.setText("Stopping\u2026");
    }

    private void setRunning(boolean running) {
        sendButton.setEnabled(!running);
        stopButton.setEnabled(running);
        input.setEnabled(!running);
        if (!running) {
            statusLabel.setText("Ready");
            removeLiveThinking();
        }
    }

    public void newConversation() {
        agentLoop.reset();
        transcript.clearRows();
        log.clear();
        currentToolCard = null;
        addWelcome();
        if (session != null) {
            session.requestCount = 0;
            session.toolCallCount = 0;
            notifyHost();
        }
    }

    // ---- Public API for templates, context-menu seeding, persistence --------

    public void applyTemplate(String name, String instructions) {
        this.templateName = name == null ? "Blank" : name;
        agentLoop.setSystemAddendum(instructions);
        if (instructions != null && !instructions.trim().isEmpty()) {
            Chip chip = new Chip("Template \u00b7 " + this.templateName, Theme.accent(),
                    Theme.blend(Theme.surface(), Theme.accent(), 0.16));
            JPanel row = new JPanel(new BorderLayout());
            row.setOpaque(false);
            row.add(chip, BorderLayout.WEST);
            transcript.addRow(row);
        }
    }

    /** Seed a session created from a right-click "Send to Cybernexis" on a request. */
    public void seedWithRequest(burp.api.montoya.http.message.HttpRequestResponse hrr) {
        int id = ctx.messages.register(hrr, "context-menu");
        String label;
        try {
            label = hrr.request().method() + " " + hrr.request().url();
        } catch (RuntimeException e) {
            label = "request";
        }
        Chip chip = new Chip("Loaded " + label + "  (message_id " + id + ")", Theme.text(),
                Theme.blend(Theme.surface(), Theme.accent(), 0.12));
        JPanel row = new JPanel(new BorderLayout());
        row.setOpaque(false);
        row.add(chip, BorderLayout.WEST);
        transcript.addRow(row);
        transcript.addRow(new HttpExchangeView(ctx.api, hrr));
        try {
            String host = com.cybernexis.agent.tools.Focus.hostOf(hrr.request().url());
            if (host != null) {
                agentLoop.setFocusHost(host);
                showFocusChip(host);
            }
        } catch (RuntimeException ignored) {
        }
        input.setText("Analyze the HTTP request/response with message_id " + id
                + " for security vulnerabilities. Start by inspecting it, then test the most promising issues.");
        input.requestFocusInWindow();
    }

    public Mode getMode() {
        return mode;
    }

    public String getTemplateName() {
        return templateName;
    }

    public java.util.List<Map<String, Object>> getLog() {
        return new java.util.ArrayList<>(log);
    }

    public java.util.List<Map<String, Object>> snapshotConversation() {
        return agentLoop.snapshotConversation();
    }

    public String getSystemAddendum() {
        return agentLoop.getSystemAddendum();
    }

    public String getFocusHost() {
        return agentLoop.getFocusHost();
    }

    public java.util.Map<String, String> snapshotVariables() {
        return agentLoop.snapshotVariables();
    }

    /** Rebuild a session from persisted state (no agent run). */
    public void restore(Mode restoredMode, String template, String instructions,
                        java.util.List<Map<String, Object>> conversation,
                        java.util.List<Map<String, Object>> savedLog, String focusHost,
                        java.util.Map<String, String> variables) {
        this.mode = restoredMode == null ? this.mode : restoredMode;
        modeCombo.setSelectedItem(this.mode);
        this.templateName = template == null ? "Blank" : template;
        agentLoop.setSystemAddendum(instructions);
        agentLoop.setFocusHost(focusHost);
        agentLoop.restoreVariables(variables);
        agentLoop.restoreConversation(conversation);

        transcript.clearRows();
        log.clear();
        if (savedLog != null) {
            for (Map<String, Object> rec : savedLog) {
                replayRecord(rec);
                log.add(rec);
            }
        }
        if (focusHost != null && !focusHost.isEmpty()) {
            showFocusChip(focusHost);
        }
        SwingUtilities.invokeLater(() -> {
            stickToBottom = true;
            autoScroll();
        });
    }

    private void replayRecord(Map<String, Object> rec) {
        String type = String.valueOf(rec.get("type"));
        switch (type) {
            case "user":
                addUserBubble(str(rec.get("text")));
                break;
            case "thought":
                transcript.addRow(thoughtLabel(str(rec.get("text"))));
                break;
            case "tool":
                currentToolCard = new ToolCallCard(str(rec.get("tool")), asMap(rec.get("args")), ctx);
                transcript.addRow(currentToolCard);
                break;
            case "result":
                ToolResult tr = Boolean.TRUE.equals(rec.get("ok"))
                        ? ToolResult.ok(rec.get("data"))
                        : ToolResult.error(str(rec.get("error")));
                if (currentToolCard != null) {
                    currentToolCard.setResult(tr);
                    currentToolCard = null;
                } else {
                    ToolCallCard c = new ToolCallCard(str(rec.get("tool")), null, ctx);
                    transcript.addRow(c);
                    c.setResult(tr);
                }
                break;
            case "assistant":
                transcript.addRow(assistantBubble(str(rec.get("markdown"))));
                break;
            case "error":
                JLabel l = new JLabel(str(rec.get("text")));
                l.setForeground(Theme.danger());
                transcript.addRow(l);
                break;
            default:
                break;
        }
    }

    private void exportReport() {
        String md = buildReportMarkdown();
        javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();
        chooser.setSelectedFile(new java.io.File(safeFileName(session == null ? "task" : session.title) + ".md"));
        if (chooser.showSaveDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File file = chooser.getSelectedFile();
        boolean html = file.getName().toLowerCase().endsWith(".html") || file.getName().toLowerCase().endsWith(".htm");
        String content = html ? Markdown.toDocument(md) : md;
        try {
            java.nio.file.Files.write(file.toPath(), content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            statusLabel.setText("Exported: " + file.getName());
        } catch (java.io.IOException e) {
            statusLabel.setText("Export failed: " + e.getMessage());
        }
    }

    private String buildReportMarkdown() {
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(session == null ? com.cybernexis.agent.Branding.PRODUCT + " task" : session.title).append("\n\n");
        if (templateName != null && !templateName.equals("Blank")) {
            sb.append("_Template: ").append(templateName).append("_\n\n");
        }
        for (Map<String, Object> rec : log) {
            String type = String.valueOf(rec.get("type"));
            switch (type) {
                case "user":
                    sb.append("## User\n\n").append(str(rec.get("text"))).append("\n\n");
                    break;
                case "thought":
                    sb.append("> ").append(str(rec.get("text"))).append("\n\n");
                    break;
                case "tool":
                    sb.append("**Tool:** `").append(str(rec.get("tool"))).append("`  \n");
                    sb.append("```json\n").append(safePretty(rec.get("args"))).append("\n```\n\n");
                    break;
                case "result":
                    boolean ok = Boolean.TRUE.equals(rec.get("ok"));
                    sb.append("**Result:** ").append(ok ? "ok" : "error").append("  \n");
                    sb.append("```json\n")
                      .append(safePretty(ok ? rec.get("data") : rec.get("error")))
                      .append("\n```\n\n");
                    break;
                case "assistant":
                    sb.append("## ").append(com.cybernexis.agent.Branding.PRODUCT).append("\n\n")
                            .append(str(rec.get("markdown"))).append("\n\n");
                    break;
                case "error":
                    sb.append("**Error:** ").append(str(rec.get("text"))).append("\n\n");
                    break;
                default:
                    break;
            }
        }
        return sb.toString();
    }

    void setMode(Mode m) {
        this.mode = m;
        modeCombo.setSelectedItem(m);
    }

    private Map<String, Object> record(String type) {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("type", type);
        return m;
    }

    private void logRecord(String type, String key, Object val) {
        Map<String, Object> m = record(type);
        m.put(key, val);
        log.add(m);
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    private static String safePretty(Object o) {
        try {
            return com.cybernexis.agent.json.Json.writePretty(o);
        } catch (RuntimeException e) {
            return String.valueOf(o);
        }
    }

    private static String safeFileName(String s) {
        if (s == null || s.trim().isEmpty()) {
            return "local-ai-task";
        }
        return s.replaceAll("[^a-zA-Z0-9-_ ]", "_").trim().replaceAll("\\s+", "-");
    }

    // ---- AgentLoop.Listener (all callbacks arrive off the EDT) ---------------

    @Override
    public void onStatus(String status) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(status));
    }

    @Override
    public void onModelToken(String token) {
        SwingUtilities.invokeLater(() -> {
            ensureLiveThinking();
            liveThinkingText.append(token);
            autoScroll();
        });
    }

    @Override
    public void onTurnParsed(int step, ToolCall call) {
        SwingUtilities.invokeLater(() -> {
            removeLiveThinking();
            if (!call.isFinal()) {
                if (call.thought != null && !call.thought.isEmpty()) {
                    transcript.addRow(thoughtLabel(call.thought));
                    logRecord("thought", "text", call.thought);
                }
                currentToolCard = new ToolCallCard(call.tool, call.args, ctx);
                transcript.addRow(currentToolCard);
                Map<String, Object> rec = record("tool");
                rec.put("tool", call.tool);
                rec.put("args", call.args);
                log.add(rec);
                autoScroll();
            }
        });
    }

    @Override
    public void onToolResult(String tool, ToolResult result) {
        SwingUtilities.invokeLater(() -> {
            if (currentToolCard != null) {
                currentToolCard.setResult(result);
                currentToolCard = null;
            } else {
                ToolCallCard card = new ToolCallCard(tool, null, ctx);
                transcript.addRow(card);
                card.setResult(result);
            }
            if (session != null) {
                session.toolCallCount++;
                notifyHost();
            }
            Map<String, Object> rec = record("result");
            rec.put("tool", tool);
            rec.put("ok", result.ok);
            if (result.ok) {
                rec.put("data", result.data);
            } else {
                rec.put("error", result.error);
            }
            log.add(rec);
            autoScroll();
        });
    }

    @Override
    public void onFinalAnswer(String markdown) {
        SwingUtilities.invokeLater(() -> {
            removeLiveThinking();
            transcript.addRow(assistantBubble(markdown));
            logRecord("assistant", "markdown", markdown);
            autoScroll();
        });
    }

    @Override
    public void onError(String message) {
        SwingUtilities.invokeLater(() -> {
            removeLiveThinking();
            RoundedPanel card = new RoundedPanel(new BorderLayout(0, 4));
            card.setArc(12).setFill(Theme.blend(Theme.surface(), Theme.danger(), 0.14))
                    .setLine(Theme.blend(Theme.border(), Theme.danger(), 0.4));
            card.setBorder(Theme.pad(8, 12, 8, 12));
            card.setAlignmentX(LEFT_ALIGNMENT);

            JLabel head = new JLabel("Error");
            head.setForeground(Theme.danger());
            head.setFont(Theme.bold(12f));

            JTextArea body = new JTextArea(message == null ? "(no message)" : message);
            body.setEditable(false);
            body.setLineWrap(true);
            body.setWrapStyleWord(true);
            body.setOpaque(false);
            body.setFont(Theme.plain(12f));
            body.setForeground(Theme.text());

            card.add(head, BorderLayout.NORTH);
            card.add(body, BorderLayout.CENTER);
            transcript.addRow(card);
            logRecord("error", "text", message == null ? "(no message)" : message);
            statusLabel.setText("Error");
            autoScroll();
        });
    }

    @Override
    public void onLogEvent(Map<String, Object> event) {
        activityLog.log(event);
    }

    @Override
    public boolean confirmAction(ToolDescriptor descriptor, Map<String, Object> args) {
        Mode m = this.mode;
        if (m == Mode.AUTO) {
            addAutoChip(descriptor.name, "Auto");
            return true;
        }
        if (m == Mode.SMART && !HIGH_IMPACT.contains(descriptor.name)) {
            addAutoChip(descriptor.name, "Smart");
            return true;
        }
        boolean escalated = (m == Mode.SMART);
        final ApprovalCard[] holder = new ApprovalCard[1];
        try {
            SwingUtilities.invokeAndWait(() -> {
                ApprovalCard card = new ApprovalCard(descriptor.name, args, escalated);
                holder[0] = card;
                pendingApproval = card;
                transcript.addRow(card);
                autoScroll();
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return false;
        }
        boolean approved = holder[0].awaitDecision();
        pendingApproval = null;
        return approved;
    }

    // ---- Transcript element builders ----------------------------------------

    private void addUserBubble(String text) {
        RoundedPanel bubble = new RoundedPanel(new BorderLayout());
        bubble.setArc(14).setFill(Theme.userBubble()).setLine(Theme.blend(Theme.border(), Theme.accent(), 0.2));
        bubble.setBorder(Theme.pad(8, 12, 8, 12));
        bubble.setAlignmentX(LEFT_ALIGNMENT);
        MarkdownView md = new MarkdownView();
        md.setMarkdown(text);
        bubble.add(md, BorderLayout.CENTER);

        JPanel row = new JPanel(new BorderLayout());
        row.setOpaque(false);
        row.setAlignmentX(LEFT_ALIGNMENT);
        JLabel who = roleLabel("You");
        row.add(who, BorderLayout.NORTH);
        row.add(bubble, BorderLayout.CENTER);
        transcript.addRow(row);
        autoScroll();
    }

    private JComponent assistantBubble(String markdown) {
        RoundedPanel bubble = new RoundedPanel(new BorderLayout());
        bubble.setArc(14).setFill(Theme.surface()).setLine(Theme.border());
        bubble.setBorder(Theme.pad(8, 12, 8, 12));
        bubble.setAlignmentX(LEFT_ALIGNMENT);
        MarkdownView md = new MarkdownView();
        md.setMarkdown(markdown);
        bubble.add(md, BorderLayout.CENTER);

        JPanel row = new JPanel(new BorderLayout());
        row.setOpaque(false);
        row.setAlignmentX(LEFT_ALIGNMENT);
        row.add(roleLabel(com.cybernexis.agent.Branding.SHORT), BorderLayout.NORTH);
        row.add(bubble, BorderLayout.CENTER);
        return row;
    }

    private JLabel roleLabel(String name) {
        JLabel l = new JLabel(name);
        l.setForeground(name.equals("You") ? Theme.accent() : Theme.mutedText());
        l.setFont(Theme.bold(11f));
        l.setBorder(Theme.pad(6, 2, 3, 2));
        return l;
    }

    private JComponent thoughtLabel(String thought) {
        JTextArea t = new JTextArea(thought);
        t.setEditable(false);
        t.setLineWrap(true);
        t.setWrapStyleWord(true);
        t.setOpaque(false);
        t.setBorder(Theme.pad(4, 2, 2, 2));
        t.setFont(Theme.baseFont().deriveFont(java.awt.Font.ITALIC, 12f));
        t.setForeground(Theme.mutedText());
        t.setAlignmentX(LEFT_ALIGNMENT);
        return t;
    }

    private void addAutoChip(String tool, String by) {
        SwingUtilities.invokeLater(() -> {
            Chip chip = new Chip("\u2713 Approved by " + by + " mode \u00b7 " + ToolNames.displayName(tool),
                    Theme.success(), Theme.blend(Theme.surface(), Theme.success(), 0.16))
                    .withDot(Theme.success());
            JPanel row = new JPanel(new BorderLayout());
            row.setOpaque(false);
            row.setAlignmentX(LEFT_ALIGNMENT);
            row.add(chip, BorderLayout.WEST);
            transcript.addRow(row);
            autoScroll();
        });
    }

    private void ensureLiveThinking() {
        if (liveThinking != null) {
            return;
        }
        liveThinkingText = new JTextArea();
        liveThinkingText.setEditable(false);
        liveThinkingText.setLineWrap(true);
        liveThinkingText.setWrapStyleWord(true);
        liveThinkingText.setFont(Theme.monoFont());
        liveThinkingText.setForeground(Theme.mutedText());
        liveThinkingText.setOpaque(false);

        RoundedPanel panel = new RoundedPanel(new BorderLayout());
        panel.setArc(12).setFill(Theme.surface()).setLine(Theme.border());
        panel.setBorder(Theme.pad(8, 12, 8, 12));
        panel.setAlignmentX(LEFT_ALIGNMENT);
        JLabel head = new JLabel("thinking\u2026");
        head.setForeground(Theme.mutedText());
        head.setFont(Theme.bold(11f));
        panel.add(head, BorderLayout.NORTH);
        panel.add(liveThinkingText, BorderLayout.CENTER);
        liveThinking = panel;
        liveThinkingRow = transcript.addRow(panel);
    }

    private void removeLiveThinking() {
        if (liveThinking != null) {
            transcript.removeRow(liveThinkingRow);
            liveThinking = null;
            liveThinkingRow = null;
            liveThinkingText = null;
        }
    }

    private void autoScroll() {
        if (!stickToBottom) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            Rectangle bottom = new Rectangle(0, transcript.getHeight() - 1, 1, 1);
            transcript.scrollRectToVisible(bottom);
        });
    }

    private void notifyHost() {
        if (host != null && session != null) {
            SwingUtilities.invokeLater(() -> host.onSessionActivity(session));
        }
    }

    private static Mode parseMode(String s) {
        if (s == null) {
            return Mode.SMART;
        }
        switch (s.trim().toLowerCase()) {
            case "manual":
                return Mode.MANUAL;
            case "auto":
                return Mode.AUTO;
            default:
                return Mode.SMART;
        }
    }

    private static String deriveTitle(String text) {
        String t = text.replaceAll("\\s+", " ").trim();
        if (t.length() > 42) {
            t = t.substring(0, 42) + "\u2026";
        }
        return t;
    }

    // ---- Width-tracking transcript container --------------------------------

    private static final class TranscriptPanel extends JPanel implements Scrollable {
        TranscriptPanel() {
            setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
            add(Box.createVerticalGlue());
        }

        /** Wraps the row so BoxLayout never stretches it vertically; returns the wrapper. */
        Component addRow(Component c) {
            MaxHeightRow wrapper = new MaxHeightRow(c);
            add(wrapper, getComponentCount() - 1);
            add(Box.createVerticalStrut(6), getComponentCount() - 1);
            revalidate();
            repaint();
            return wrapper;
        }

        void removeRow(Component wrapper) {
            if (wrapper == null) {
                return;
            }
            remove(wrapper);
            revalidate();
            repaint();
        }

        void clearRows() {
            removeAll();
            add(Box.createVerticalGlue());
            revalidate();
            repaint();
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return Math.max(48, visibleRect.height - 32);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    /** A full-width row whose height tracks its content's preferred height. */
    private static final class MaxHeightRow extends JPanel {
        MaxHeightRow(Component content) {
            super(new BorderLayout());
            setOpaque(false);
            setAlignmentX(LEFT_ALIGNMENT);
            add(content, BorderLayout.CENTER);
        }

        @Override
        public Dimension getMaximumSize() {
            return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
        }
    }
}
