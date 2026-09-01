/*
 * Activity log tab: shows every agent turn and tool result as one-line JSON,
 * mirrored to Burp's own logging output.
 */
package com.cybernexis.agent.ui;

import java.awt.BorderLayout;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import burp.api.montoya.logging.Logging;
import com.cybernexis.agent.json.Json;

public class ToolActivityLog extends JPanel {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final JTextArea area = new JTextArea();
    private final Logging logging;

    public ToolActivityLog(Logging logging) {
        super(new BorderLayout());
        this.logging = logging;
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12));

        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> area.setText(""));
        JPanel top = new JPanel(new BorderLayout());
        top.add(clear, BorderLayout.EAST);

        add(top, BorderLayout.NORTH);
        add(new JScrollPane(area), BorderLayout.CENTER);
    }

    public void log(Map<String, Object> event) {
        String line = "[" + LocalTime.now().format(TIME) + "] " + Json.write(event);
        if (logging != null) {
            try {
                logging.logToOutput(line);
            } catch (RuntimeException ignored) {
            }
        }
        SwingUtilities.invokeLater(() -> {
            area.append(line + "\n");
            area.setCaretPosition(area.getDocument().getLength());
        });
    }
}
