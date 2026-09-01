/*
 * Inline tool-call entry: "used · <tool>" with a status chip and collapsible
 * details (arguments, result JSON, and, when the tool touched an HTTP message,
 * Burp's native request/response editors).
 */
package com.cybernexis.agent.ui;

import java.awt.Component;
import java.awt.Dimension;
import java.util.Map;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import com.cybernexis.agent.json.Json;
import com.cybernexis.agent.tools.MessageStore;
import com.cybernexis.agent.tools.ToolContext;
import com.cybernexis.agent.tools.ToolResult;

public class ToolCallCard extends JPanel {

    private final ToolContext ctx;
    private final Map<String, Object> args;
    private final CollapsibleCard card;
    private final Chip statusChip;
    private final JPanel body = new JPanel();

    public ToolCallCard(String tool, Map<String, Object> args, ToolContext ctx) {
        super(new java.awt.BorderLayout());
        setOpaque(false);
        setAlignmentX(LEFT_ALIGNMENT);
        setBorder(Theme.pad(3, 0, 3, 0));
        this.ctx = ctx;
        this.args = args;

        JPanel title = new JPanel();
        title.setOpaque(false);
        title.setLayout(new BoxLayout(title, BoxLayout.X_AXIS));
        JLabel used = new JLabel("used");
        used.setForeground(Theme.mutedText());
        used.setFont(Theme.plain(12f));
        Chip toolChip = new Chip(tool, Theme.accent(),
                Theme.blend(Theme.surface(), Theme.accent(), 0.16));
        title.add(used);
        title.add(Box.createHorizontalStrut(8));
        title.add(toolChip);

        statusChip = new Chip("running\u2026", Theme.mutedText(),
                Theme.blend(Theme.surface(), Theme.mutedText(), 0.18));

        card = new CollapsibleCard(title, statusChip);

        body.setOpaque(false);
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        if (args != null && !args.isEmpty()) {
            body.add(sectionLabel("Arguments"));
            body.add(codeArea(safePretty(args)));
        }
        card.setBody(body);

        add(card, java.awt.BorderLayout.CENTER);
    }

    public void setResult(ToolResult result) {
        if (result.ok) {
            statusChip.set("ok", Theme.success(), Theme.blend(Theme.surface(), Theme.success(), 0.18));
        } else {
            statusChip.set("error", Theme.danger(), Theme.blend(Theme.surface(), Theme.danger(), 0.18));
        }

        body.add(Box.createVerticalStrut(8));
        if (result.ok) {
            if (result.data != null) {
                body.add(sectionLabel("Result"));
                body.add(codeArea(truncate(safePretty(result.data), 4000)));
            }
            Component exchange = buildExchange(result);
            if (exchange != null) {
                body.add(Box.createVerticalStrut(8));
                body.add(sectionLabel("HTTP exchange"));
                body.add(exchange);
                card.setExpanded(true);
            }
        } else {
            body.add(sectionLabel("Error"));
            JTextArea err = codeArea(result.error == null ? "(no message)" : result.error);
            err.setForeground(Theme.danger());
            body.add(err);
        }
        revalidate();
        repaint();
    }

    private Component buildExchange(ToolResult result) {
        Integer id = candidateMessageId(result);
        if (id == null || ctx == null) {
            return null;
        }
        try {
            MessageStore.Entry entry = ctx.messages.get(id);
            if (entry == null || entry.message == null) {
                return null;
            }
            return new HttpExchangeView(ctx.api, entry.message);
        } catch (RuntimeException e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private Integer candidateMessageId(ToolResult result) {
        if (result.data instanceof Map) {
            Object mid = ((Map<String, Object>) result.data).get("message_id");
            Integer parsed = asInt(mid);
            if (parsed != null) {
                return parsed;
            }
        }
        Integer fromArgs = asInt(args == null ? null : args.get("message_id"));
        if (fromArgs != null) {
            return fromArgs;
        }
        return asInt(args == null ? null : args.get("request_id"));
    }

    private static Integer asInt(Object o) {
        if (o instanceof Number) {
            return ((Number) o).intValue();
        }
        if (o instanceof String) {
            try {
                return Integer.parseInt(((String) o).trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static String safePretty(Object o) {
        try {
            return Json.writePretty(o);
        } catch (RuntimeException e) {
            return String.valueOf(o);
        }
    }

    private static JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(Theme.mutedText());
        l.setFont(Theme.bold(11f));
        l.setAlignmentX(LEFT_ALIGNMENT);
        l.setBorder(Theme.pad(0, 0, 2, 0));
        return l;
    }

    private static JTextArea codeArea(String text) {
        JTextArea a = new JTextArea(text);
        a.setEditable(false);
        a.setLineWrap(true);
        a.setWrapStyleWord(false);
        a.setFont(Theme.monoFont());
        a.setForeground(Theme.text());
        a.setBackground(Theme.surfaceAlt());
        a.setBorder(Theme.pad(6, 8, 6, 8));
        a.setAlignmentX(LEFT_ALIGNMENT);
        a.setCaretPosition(0);
        return a;
    }

    private static String truncate(String s, int max) {
        if (s == null || s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "\n\u2026[" + (s.length() - max) + " more chars]";
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }
}
