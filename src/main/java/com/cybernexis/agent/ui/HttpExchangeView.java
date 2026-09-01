/*
 * Embeds Burp's own request/response editors (read-only) for a captured
 * HttpRequestResponse, giving the chat the same syntax-highlighted "HTTP
 * Exchange" viewer that Repeater/Proxy use.
 */
package com.cybernexis.agent.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

public class HttpExchangeView extends JPanel {

    public HttpExchangeView(MontoyaApi api, HttpRequestResponse hrr) {
        super(new BorderLayout());
        setOpaque(false);

        JTabbedPane tabs = new JTabbedPane();
        try {
            HttpRequestEditor requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
            if (hrr.request() != null) {
                requestEditor.setRequest(hrr.request());
            }
            tabs.addTab("Request", requestEditor.uiComponent());

            if (hrr.hasResponse() && hrr.response() != null) {
                HttpResponseEditor responseEditor =
                        api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
                responseEditor.setResponse(hrr.response());
                tabs.addTab("Response", responseEditor.uiComponent());
            }
        } catch (RuntimeException e) {
            tabs.addTab("HTTP", new javax.swing.JLabel("Editor unavailable: " + e.getMessage()));
        }

        tabs.setPreferredSize(new Dimension(680, 320));
        add(tabs, BorderLayout.CENTER);
    }

    @Override
    public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }
}
