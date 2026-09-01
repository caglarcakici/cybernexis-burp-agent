/*
 * A JPanel that paints a rounded rectangle background (and optional border),
 * used for chat bubbles and cards. Honors an arc radius and stays transparent
 * outside the rounded shape so it blends with the transcript background.
 */
package com.cybernexis.agent.ui;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.LayoutManager;
import java.awt.RenderingHints;

import javax.swing.JPanel;

public class RoundedPanel extends JPanel {

    private int arc = 14;
    private Color fill;
    private Color lineColor;

    public RoundedPanel(LayoutManager layout) {
        super(layout);
        setOpaque(false);
    }

    public RoundedPanel setArc(int arc) {
        this.arc = arc;
        return this;
    }

    public RoundedPanel setFill(Color fill) {
        this.fill = fill;
        return this;
    }

    public RoundedPanel setLine(Color line) {
        this.lineColor = line;
        return this;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth();
        int h = getHeight();
        if (fill != null) {
            g2.setColor(fill);
            g2.fillRoundRect(0, 0, w - 1, h - 1, arc, arc);
        }
        if (lineColor != null) {
            g2.setColor(lineColor);
            g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc);
        }
        g2.dispose();
        super.paintComponent(g);
    }
}
