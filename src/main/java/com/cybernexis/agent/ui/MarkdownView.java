/*
 * A read-only, transparent, selectable HTML view that renders markdown and
 * computes its wrapped height for the width it is given (so it behaves well in a
 * vertically stacked, width-tracking transcript).
 */
package com.cybernexis.agent.ui;

import java.awt.Desktop;
import java.awt.Dimension;

import javax.swing.JEditorPane;
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.html.HTMLEditorKit;

public class MarkdownView extends JEditorPane {

    private String markdown = "";

    public MarkdownView() {
        setContentType("text/html");
        setEditable(false);
        setOpaque(false);
        setBorder(null);
        setEditorKit(new HTMLEditorKit());
        putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        addHyperlinkListener(this::onLink);
    }

    public void setMarkdown(String md) {
        this.markdown = md == null ? "" : md;
        setText(Markdown.toDocument(this.markdown));
        setCaretPosition(0);
        revalidate();
    }

    public String getMarkdown() {
        return markdown;
    }

    private void onLink(HyperlinkEvent e) {
        if (e.getEventType() != HyperlinkEvent.EventType.ACTIVATED || e.getURL() == null) {
            return;
        }
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(e.getURL().toURI());
            }
        } catch (RuntimeException | java.io.IOException | java.net.URISyntaxException ignored) {
            // Opening a browser is best-effort.
        }
    }

    @Override
    public Dimension getPreferredSize() {
        Dimension d = super.getPreferredSize();
        int w = getWidth();
        if (w > 0) {
            // Recompute the wrapped height for the current width.
            setSize(w, Short.MAX_VALUE);
            d = super.getPreferredSize();
            d.width = w;
        }
        return d;
    }

    @Override
    public Dimension getMaximumSize() {
        Dimension pref = getPreferredSize();
        return new Dimension(Integer.MAX_VALUE, pref.height);
    }
}
