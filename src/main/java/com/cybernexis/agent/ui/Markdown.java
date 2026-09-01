/*
 * Markdown -> HTML rendering for the chat transcript. Uses flexmark (bundled in
 * the jar) with GFM tables and strikethrough, then wraps the output in a small
 * theme-aware stylesheet compatible with Swing's HTMLEditorKit.
 */
package com.cybernexis.agent.ui;

import java.awt.Color;
import java.util.Arrays;

import com.vladsch.flexmark.ext.gfm.strikethrough.StrikethroughExtension;
import com.vladsch.flexmark.ext.tables.TablesExtension;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.ast.Node;
import com.vladsch.flexmark.util.data.MutableDataSet;

public final class Markdown {

    private static final Parser PARSER;
    private static final HtmlRenderer RENDERER;

    static {
        MutableDataSet options = new MutableDataSet();
        options.set(Parser.EXTENSIONS, Arrays.asList(
                TablesExtension.create(),
                StrikethroughExtension.create()));
        // Render local model output as text only; never inject raw HTML into the pane.
        options.set(HtmlRenderer.ESCAPE_HTML, true);
        options.set(HtmlRenderer.SOFT_BREAK, "<br/>\n");
        PARSER = Parser.builder(options).build();
        RENDERER = HtmlRenderer.builder(options).build();
    }

    private Markdown() {
    }

    /** Render markdown source to an HTML fragment (no <html> wrapper). */
    public static String toHtmlFragment(String markdown) {
        if (markdown == null) {
            return "";
        }
        Node document = PARSER.parse(markdown);
        return RENDERER.render(document);
    }

    /** Full HTML document with a theme-aware stylesheet for a JEditorPane. */
    public static String toDocument(String markdown) {
        Color text = Theme.text();
        Color muted = Theme.mutedText();
        Color border = Theme.border();
        Color codeBg = Theme.surfaceAlt();
        Color headBg = Theme.blend(Theme.surfaceAlt(), Theme.accent(), 0.12);
        Color link = Theme.accent();
        int fontSize = Theme.baseFont().getSize();

        String css = ""
                + "body{font-family:sans-serif;font-size:" + fontSize + "pt;color:" + Theme.hex(text)
                + ";margin:0;padding:0;}"
                + "p{margin:2px 0 8px 0;}"
                + "h1{font-size:" + (fontSize + 5) + "pt;margin:6px 0 6px 0;}"
                + "h2{font-size:" + (fontSize + 3) + "pt;margin:6px 0 5px 0;}"
                + "h3{font-size:" + (fontSize + 1) + "pt;margin:6px 0 4px 0;}"
                + "h4,h5,h6{font-size:" + fontSize + "pt;margin:5px 0 4px 0;}"
                + "ul,ol{margin:2px 0 8px 0;}"
                + "li{margin:1px 0;}"
                + "a{color:" + Theme.hex(link) + ";}"
                + "code{font-family:monospaced;background:" + Theme.hex(codeBg)
                + ";padding:1px 3px;}"
                + "pre{font-family:monospaced;background:" + Theme.hex(codeBg)
                + ";padding:6px;border:1px solid " + Theme.hex(border) + ";}"
                + "blockquote{margin:4px 0;padding:2px 8px;color:" + Theme.hex(muted)
                + ";border-left:3px solid " + Theme.hex(border) + ";}"
                + "table{border:1px solid " + Theme.hex(border) + ";border-collapse:collapse;margin:4px 0 8px 0;}"
                + "th{background:" + Theme.hex(headBg) + ";border:1px solid " + Theme.hex(border)
                + ";padding:3px 8px;text-align:left;}"
                + "td{border:1px solid " + Theme.hex(border) + ";padding:3px 8px;}"
                + "hr{border:0;border-top:1px solid " + Theme.hex(border) + ";}";

        return "<html><head><style>" + css + "</style></head><body>"
                + toHtmlFragment(markdown) + "</body></html>";
    }
}
