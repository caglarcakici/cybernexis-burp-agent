/*
 * Small theming helper. Burp Suite renders its UI with FlatLaf, so we read
 * colors and fonts from UIManager and derive a few chat-specific tones. This
 * keeps the chat UI consistent with whatever Burp theme (light/dark) is active.
 */
package com.cybernexis.agent.ui;

import java.awt.Color;
import java.awt.Font;

import javax.swing.UIManager;
import javax.swing.border.Border;
import javax.swing.BorderFactory;

public final class Theme {

    private Theme() {
    }

    public static Color panel() {
        return or(UIManager.getColor("Panel.background"), new Color(0x2B2B2B));
    }

    public static Color surface() {
        // Slightly raised background used for bubbles/cards.
        return shift(panel(), isDark() ? 0.06 : -0.03);
    }

    public static Color surfaceAlt() {
        return shift(panel(), isDark() ? 0.12 : -0.06);
    }

    public static Color userBubble() {
        Color a = accent();
        return isDark() ? blend(panel(), a, 0.22) : blend(panel(), a, 0.12);
    }

    public static Color border() {
        return or(UIManager.getColor("Component.borderColor"),
                or(UIManager.getColor("Separator.foreground"), shift(panel(), isDark() ? 0.18 : -0.15)));
    }

    public static Color text() {
        return or(UIManager.getColor("Label.foreground"), new Color(0xDD, 0xDD, 0xDD));
    }

    public static Color mutedText() {
        return blend(text(), panel(), 0.45);
    }

    public static Color accent() {
        Color c = UIManager.getColor("Component.accentColor");
        if (c == null) {
            c = UIManager.getColor("Component.focusColor");
        }
        // Burp's signature orange as a fallback.
        return c != null ? c : new Color(0xE8, 0x6B, 0x2C);
    }

    public static Color success() {
        return new Color(0x3F, 0xA9, 0x5C);
    }

    public static Color warning() {
        return new Color(0xD9, 0x8A, 0x1F);
    }

    public static Color danger() {
        return new Color(0xCF, 0x4B, 0x3C);
    }

    public static Font baseFont() {
        Font f = UIManager.getFont("Label.font");
        return f != null ? f : new Font("SansSerif", Font.PLAIN, 13);
    }

    public static Font monoFont() {
        return new Font(Font.MONOSPACED, Font.PLAIN, Math.max(11, baseFont().getSize() - 1));
    }

    public static Font bold(float size) {
        return baseFont().deriveFont(Font.BOLD, size);
    }

    public static Font plain(float size) {
        return baseFont().deriveFont(Font.PLAIN, size);
    }

    public static Border pad(int top, int left, int bottom, int right) {
        return BorderFactory.createEmptyBorder(top, left, bottom, right);
    }

    public static boolean isDark() {
        Color bg = or(UIManager.getColor("Panel.background"), new Color(0x2B2B2B));
        return luminance(bg) < 0.5;
    }

    public static String hex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    // ---- color math ---------------------------------------------------------

    private static Color or(Color c, Color fallback) {
        return c != null ? c : fallback;
    }

    /** Lighten (positive) or darken (negative) a color by a fraction. */
    public static Color shift(Color c, double frac) {
        if (frac >= 0) {
            return blend(c, Color.WHITE, frac);
        }
        return blend(c, Color.BLACK, -frac);
    }

    public static Color blend(Color a, Color b, double t) {
        t = Math.max(0, Math.min(1, t));
        int r = (int) Math.round(a.getRed() * (1 - t) + b.getRed() * t);
        int g = (int) Math.round(a.getGreen() * (1 - t) + b.getGreen() * t);
        int bl = (int) Math.round(a.getBlue() * (1 - t) + b.getBlue() * t);
        return new Color(clamp(r), clamp(g), clamp(bl));
    }

    private static int clamp(int v) {
        return Math.max(0, Math.min(255, v));
    }

    private static double luminance(Color c) {
        return (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue()) / 255.0;
    }
}
