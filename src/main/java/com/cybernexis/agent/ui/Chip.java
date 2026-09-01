/*
 * A small rounded "chip" label with an optional leading dot, used for tool tags,
 * status badges (auto-approved, escalated), and counts.
 */
package com.cybernexis.agent.ui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

import javax.swing.JLabel;

public class Chip extends JLabel {

    private Color chipBg;
    private Color dot;

    public Chip(String text, Color fg, Color bg) {
        super(text);
        this.chipBg = bg;
        setForeground(fg);
        setOpaque(false);
        setFont(Theme.plain(11f));
        setBorder(Theme.pad(2, 9, 3, 9));
    }

    public Chip withDot(Color dotColor) {
        this.dot = dotColor;
        setBorder(Theme.pad(2, 20, 3, 9));
        return this;
    }

    /** Recolor and relabel in place (e.g. running -> ok/error). */
    public void set(String text, Color fg, Color bg) {
        setText(text);
        setForeground(fg);
        this.chipBg = bg;
        revalidate();
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int h = getHeight();
        if (chipBg != null) {
            g2.setColor(chipBg);
            g2.fillRoundRect(0, 0, getWidth() - 1, h - 1, h, h);
        }
        if (dot != null) {
            g2.setColor(dot);
            int d = 7;
            g2.fillOval(9, (h - d) / 2, d, d);
        }
        g2.dispose();
        super.paintComponent(g);
    }

    @Override
    public Dimension getMaximumSize() {
        return getPreferredSize();
    }
}
