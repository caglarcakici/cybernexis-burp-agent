/*
 * A rounded card with a clickable header that expands/collapses a body area.
 * Used for inline tool-call entries ("used · Send Request" -> Show details).
 */
package com.cybernexis.agent.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class CollapsibleCard extends RoundedPanel {

    private final JLabel arrow = new JLabel("\u203A");
    private final JPanel header = new JPanel(new BorderLayout(8, 0));
    private final JPanel bodyHolder = new JPanel(new BorderLayout());
    private final JLabel toggleHint = new JLabel("Show details");
    private boolean expanded;

    public CollapsibleCard(Component title, Component accessory) {
        super(new BorderLayout());
        setArc(12);
        setFill(Theme.surface());
        setLine(Theme.border());
        setBorder(Theme.pad(6, 10, 6, 10));
        setAlignmentX(LEFT_ALIGNMENT);

        arrow.setForeground(Theme.mutedText());
        arrow.setFont(Theme.bold(13f));
        arrow.setBorder(Theme.pad(0, 0, 0, 4));

        JPanel left = new JPanel();
        left.setOpaque(false);
        left.setLayout(new BoxLayout(left, BoxLayout.X_AXIS));
        left.add(arrow);
        left.add(title);

        JPanel right = new JPanel();
        right.setOpaque(false);
        right.setLayout(new BoxLayout(right, BoxLayout.X_AXIS));
        toggleHint.setForeground(Theme.mutedText());
        toggleHint.setFont(Theme.plain(11f));
        if (accessory != null) {
            right.add(accessory);
        }
        right.add(javax.swing.Box.createHorizontalStrut(10));
        right.add(toggleHint);

        header.setOpaque(false);
        header.add(left, BorderLayout.WEST);
        header.add(right, BorderLayout.EAST);
        header.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        header.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                setExpanded(!expanded);
            }
        });

        bodyHolder.setOpaque(false);
        bodyHolder.setBorder(Theme.pad(8, 4, 2, 2));
        bodyHolder.setVisible(false);

        add(header, BorderLayout.NORTH);
        add(bodyHolder, BorderLayout.CENTER);
    }

    public void setBody(Component body) {
        bodyHolder.removeAll();
        if (body != null) {
            bodyHolder.add(body, BorderLayout.CENTER);
        }
    }

    public void setExpanded(boolean value) {
        this.expanded = value;
        arrow.setText(value ? "\u2304" : "\u203A");
        toggleHint.setText(value ? "Hide details" : "Show details");
        bodyHolder.setVisible(value);
        revalidate();
        repaint();
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }
}
