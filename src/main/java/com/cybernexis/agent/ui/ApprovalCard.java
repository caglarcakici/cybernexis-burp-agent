/*
 * Inline approval prompt shown in the transcript when an action tool needs
 * confirmation. The agent's background thread blocks on awaitDecision() until
 * the user clicks Approve/Reject (or uses Ctrl+Enter / Esc).
 */
package com.cybernexis.agent.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.KeyStroke;

import com.cybernexis.agent.json.Json;

public class ApprovalCard extends RoundedPanel {

    private final CountDownLatch latch = new CountDownLatch(1);
    private volatile boolean approved;

    private final JButton approve = new JButton("Approve");
    private final JButton reject = new JButton("Reject");
    private final JLabel resolvedLabel = new JLabel();
    private final JPanel actions;

    public ApprovalCard(String toolLabel, Map<String, Object> args, boolean escalated) {
        super(new BorderLayout(0, 8));
        setArc(14);
        setFill(Theme.surface());
        setLine(Theme.blend(Theme.border(), Theme.accent(), 0.35));
        setBorder(Theme.pad(12, 14, 12, 14));
        setAlignmentX(LEFT_ALIGNMENT);

        JPanel head = new JPanel();
        head.setOpaque(false);
        head.setLayout(new BoxLayout(head, BoxLayout.Y_AXIS));

        if (escalated) {
            Chip badge = new Chip("Escalated by Smart mode \u00b7 " + toolLabel,
                    Theme.warning(), Theme.blend(Theme.surface(), Theme.warning(), 0.16))
                    .withDot(Theme.warning());
            badge.setAlignmentX(LEFT_ALIGNMENT);
            JPanel wrap = leftRow(badge);
            head.add(wrap);
            head.add(Box.createVerticalStrut(6));
        }

        JLabel title = new JLabel(com.cybernexis.agent.Branding.allowAction(toolLabel));
        title.setFont(Theme.bold(13f));
        title.setForeground(Theme.text());
        title.setAlignmentX(LEFT_ALIGNMENT);
        head.add(leftRow(title));

        if (args != null && !args.isEmpty()) {
            JLabel argsLabel = new JLabel(truncate(Json.write(args), 200));
            argsLabel.setFont(Theme.monoFont());
            argsLabel.setForeground(Theme.mutedText());
            argsLabel.setAlignmentX(LEFT_ALIGNMENT);
            head.add(Box.createVerticalStrut(4));
            head.add(leftRow(argsLabel));
        }

        actions = new JPanel();
        actions.setOpaque(false);
        actions.setLayout(new BoxLayout(actions, BoxLayout.X_AXIS));
        actions.add(Box.createHorizontalGlue());

        JLabel rejectHint = hint("esc");
        JLabel approveHint = hint("Ctrl+Enter");
        approve.putClientProperty("JButton.buttonType", "default");
        approve.setBackground(Theme.accent());
        approve.setForeground(pickReadable(Theme.accent()));

        reject.addActionListener(e -> resolve(false));
        approve.addActionListener(e -> resolve(true));

        actions.add(rejectHint);
        actions.add(Box.createHorizontalStrut(6));
        actions.add(reject);
        actions.add(Box.createHorizontalStrut(14));
        actions.add(approveHint);
        actions.add(Box.createHorizontalStrut(6));
        actions.add(approve);

        resolvedLabel.setFont(Theme.plain(12f));
        resolvedLabel.setVisible(false);

        JPanel south = new JPanel(new BorderLayout());
        south.setOpaque(false);
        south.add(actions, BorderLayout.CENTER);
        south.add(resolvedLabel, BorderLayout.WEST);

        add(head, BorderLayout.NORTH);
        add(south, BorderLayout.SOUTH);

        installKeys();
    }

    private void installKeys() {
        JComponent root = this;
        root.getInputMap(WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke("ESCAPE"), "reject");
        root.getInputMap(WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke("control ENTER"), "approve");
        root.getInputMap(WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke("meta ENTER"), "approve");
        root.getActionMap().put("reject", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                resolve(false);
            }
        });
        root.getActionMap().put("approve", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                resolve(true);
            }
        });
    }

    private void resolve(boolean value) {
        if (latch.getCount() == 0) {
            return;
        }
        this.approved = value;
        approve.setEnabled(false);
        reject.setEnabled(false);
        actions.setVisible(false);
        clearKeys();
        resolvedLabel.setVisible(true);
        if (value) {
            resolvedLabel.setText("\u2713 Approved");
            resolvedLabel.setForeground(Theme.success());
            setLine(Theme.blend(Theme.border(), Theme.success(), 0.35));
        } else {
            resolvedLabel.setText("\u2715 Rejected");
            resolvedLabel.setForeground(Theme.danger());
            setLine(Theme.blend(Theme.border(), Theme.danger(), 0.35));
        }
        revalidate();
        repaint();
        latch.countDown();
    }

    private void clearKeys() {
        getInputMap(WHEN_IN_FOCUSED_WINDOW).clear();
        getActionMap().clear();
    }

    /** Blocks the calling (agent) thread until a decision is made. */
    public boolean awaitDecision() {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
        return approved;
    }

    /** Force-resolve as rejected, e.g. when the run is stopped. */
    public void cancel() {
        resolve(false);
    }

    private static JPanel leftRow(Component c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setOpaque(false);
        p.add(c, BorderLayout.WEST);
        return p;
    }

    private static JLabel hint(String text) {
        JLabel l = new JLabel(text);
        l.setFont(Theme.plain(11f));
        l.setForeground(Theme.mutedText());
        l.setBorder(BorderFactory.createEmptyBorder());
        return l;
    }

    private static java.awt.Color pickReadable(java.awt.Color bg) {
        double lum = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) / 255.0;
        return lum < 0.55 ? java.awt.Color.WHITE : new java.awt.Color(0x1A, 0x1A, 0x1A);
    }

    private static String truncate(String s, int max) {
        if (s == null || s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "\u2026";
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }
}
