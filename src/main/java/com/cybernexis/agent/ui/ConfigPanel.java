/*
 * Settings tab: edit and persist model-provider/agent configuration and test
 * connectivity to the selected local or remote endpoint.
 */
package com.cybernexis.agent.ui;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Arrays;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import com.cybernexis.agent.Config;
import com.cybernexis.agent.ConfigStore;
import com.cybernexis.agent.ollama.OllamaClient;

public class ConfigPanel extends JPanel {

    private final Config config;
    private final ConfigStore store;

    private final JComboBox<ProviderOption> provider = new JComboBox<>(new ProviderOption[]{
            new ProviderOption(Config.PROVIDER_OLLAMA, "Ollama native"),
            new ProviderOption(Config.PROVIDER_OPENAI, "OpenAI-compatible"),
            new ProviderOption(Config.PROVIDER_ANTHROPIC, "Anthropic Messages")
    });
    private final JTextField baseUrl = new JTextField(28);
    private final JTextField chatEndpoint = new JTextField(28);
    private final JTextField modelsEndpoint = new JTextField(28);
    private final JComboBox<String> model = new JComboBox<>();
    private final JPasswordField apiToken = new JPasswordField(28);
    private final JTextField temperature = new JTextField(6);
    private final JTextField maxTokens = new JTextField(6);
    private final JTextField maxSteps = new JTextField(6);
    private final JTextField timeout = new JTextField(6);
    private final JTextField contextBudget = new JTextField(6);
    private final JComboBox<String> defaultMode = new JComboBox<>(new String[]{"manual", "smart", "auto"});
    private final JCheckBox enforceScope = new JCheckBox("Block action tools targeting out-of-scope hosts");
    private final JCheckBox passiveAiScan = new JCheckBox(
            "Passive scanner — send in-scope traffic to the selected model (off until enabled)");
    private final JLabel status = new JLabel(" ");
    private String previousProvider;

    public ConfigPanel(Config config, ConfigStore store) {
        super(new BorderLayout());
        this.config = config;
        this.store = store;
        model.setEditable(true);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        int row = 0;
        addRow(form, c, row++, "Provider protocol:", provider);
        addRow(form, c, row++, "Base URL:", baseUrl);
        addRow(form, c, row++, "Chat endpoint:", chatEndpoint);
        addRow(form, c, row++, "Models endpoint:", modelsEndpoint);
        addRow(form, c, row++, "Model:", model);
        addRow(form, c, row++, "API token (optional):", apiToken);
        addRow(form, c, row++, "Temperature:", temperature);
        addRow(form, c, row++, "Max tokens:", maxTokens);
        addRow(form, c, row++, "Max steps:", maxSteps);
        addRow(form, c, row++, "Timeout (s):", timeout);
        addRow(form, c, row++, "Context budget (chars):", contextBudget);
        addRow(form, c, row++, "Default mode:", defaultMode);

        c.gridx = 1;
        c.gridy = row++;
        form.add(enforceScope, c);
        c.gridy = row++;
        form.add(passiveAiScan, c);

        JLabel privacy = new JLabel("<html><b>Privacy:</b> Remote providers receive prompts and selected Burp traffic. "
                + "The API token is stored in Burp preferences.</html>");
        c.gridx = 0;
        c.gridy = row++;
        c.gridwidth = 2;
        form.add(privacy, c);
        c.gridwidth = 1;

        JButton test = new JButton("Test connection");
        JButton save = new JButton("Save");
        JPanel buttons = new JPanel();
        buttons.add(test);
        buttons.add(save);
        c.gridx = 1;
        c.gridy = row++;
        form.add(buttons, c);

        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        form.add(status, c);

        add(form, BorderLayout.NORTH);

        loadIntoFields();

        test.addActionListener(e -> testConnection());
        provider.addActionListener(e -> providerChanged());
        save.addActionListener(e -> {
            applyToConfig();
            store.save(config);
            status.setText("Saved.");
        });
        // Apply immediately so the scanner stops/starts without waiting for Save.
        passiveAiScan.addActionListener(e -> {
            config.passiveAiScan = passiveAiScan.isSelected();
            store.save(config);
            status.setText(config.passiveAiScan
                    ? "Passive scanner ON — in-scope responses will be sent to the selected model."
                    : "Passive scanner OFF.");
        });
    }

    private void loadIntoFields() {
        selectProvider(config.normalizedProvider());
        previousProvider = config.normalizedProvider();
        baseUrl.setText(config.baseUrl);
        chatEndpoint.setText(config.chatEndpoint);
        modelsEndpoint.setText(config.modelsEndpoint);
        model.removeAllItems();
        model.addItem(config.model);
        model.setSelectedItem(config.model);
        apiToken.setText(config.apiToken == null ? "" : config.apiToken);
        temperature.setText(String.valueOf(config.temperature));
        maxTokens.setText(String.valueOf(config.maxTokens));
        maxSteps.setText(String.valueOf(config.maxSteps));
        timeout.setText(String.valueOf(config.timeoutSeconds));
        contextBudget.setText(String.valueOf(config.contextCharBudget));
        defaultMode.setSelectedItem(config.agentMode == null ? "smart" : config.agentMode);
        enforceScope.setSelected(config.enforceScope);
        passiveAiScan.setSelected(config.passiveAiScan);
    }

    private void applyToConfig() {
        ProviderOption selectedProvider = (ProviderOption) provider.getSelectedItem();
        if (selectedProvider != null) {
            config.provider = selectedProvider.id;
        }
        config.baseUrl = baseUrl.getText().trim();
        config.chatEndpoint = chatEndpoint.getText().trim();
        config.modelsEndpoint = modelsEndpoint.getText().trim();
        Object sel = model.getSelectedItem();
        if (sel != null && !sel.toString().trim().isEmpty()) {
            config.model = sel.toString().trim();
        }
        char[] token = apiToken.getPassword();
        try {
            config.apiToken = new String(token).trim();
        } finally {
            Arrays.fill(token, '\0');
        }
        config.temperature = parseDouble(temperature.getText(), config.temperature);
        config.maxTokens = parseInt(maxTokens.getText(), config.maxTokens);
        config.maxSteps = parseInt(maxSteps.getText(), config.maxSteps);
        config.timeoutSeconds = parseInt(timeout.getText(), config.timeoutSeconds);
        config.contextCharBudget = parseInt(contextBudget.getText(), config.contextCharBudget);
        Object modeSel = defaultMode.getSelectedItem();
        config.agentMode = modeSel == null ? config.agentMode : modeSel.toString();
        config.enforceScope = enforceScope.isSelected();
        config.passiveAiScan = passiveAiScan.isSelected();
    }

    private void providerChanged() {
        ProviderOption selected = (ProviderOption) provider.getSelectedItem();
        if (selected == null) {
            return;
        }
        String current = baseUrl.getText().trim();
        String currentChat = chatEndpoint.getText().trim();
        String currentModels = modelsEndpoint.getText().trim();
        if (current.isEmpty() || (previousProvider != null
                && current.equals(Config.defaultBaseUrl(previousProvider)))) {
            baseUrl.setText(Config.defaultBaseUrl(selected.id));
        }
        if (currentChat.isEmpty() || (previousProvider != null
                && currentChat.equals(Config.defaultChatEndpoint(previousProvider)))) {
            chatEndpoint.setText(Config.defaultChatEndpoint(selected.id));
        }
        if (currentModels.isEmpty() || (previousProvider != null
                && currentModels.equals(Config.defaultModelsEndpoint(previousProvider)))) {
            modelsEndpoint.setText(Config.defaultModelsEndpoint(selected.id));
        }
        previousProvider = selected.id;
        status.setText("Using " + selected.label + ". Configure endpoints, model, and token, then test.");
    }

    private void selectProvider(String id) {
        for (int i = 0; i < provider.getItemCount(); i++) {
            ProviderOption option = provider.getItemAt(i);
            if (option.id.equals(id)) {
                provider.setSelectedIndex(i);
                return;
            }
        }
        provider.setSelectedIndex(0);
    }

    private void testConnection() {
        applyToConfig();
        status.setText("Testing " + config.normalizedBaseUrl() + " ...");
        OllamaClient client = new OllamaClient(config);
        new Thread(() -> {
            try {
                String summary = client.connectionSummary();
                List<String> models = client.listModels();
                SwingUtilities.invokeLater(() -> {
                    String selected = (String) model.getSelectedItem();
                    model.removeAllItems();
                    for (String m : models) {
                        model.addItem(m);
                    }
                    if (selected != null) {
                        model.setSelectedItem(selected);
                    }
                    status.setText("OK — " + summary + ", " + models.size() + " model(s) found.");
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                        status.setText("Failed: " + ex.getMessage()));
            }
        }, "cybernexis-conn-test").start();
    }

    private static void addRow(JPanel form, GridBagConstraints c, int row, String label, java.awt.Component field) {
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 1;
        form.add(new JLabel(label), c);
        c.gridx = 1;
        form.add(field, c);
    }

    private static int parseInt(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static double parseDouble(String s, double def) {
        try {
            return Double.parseDouble(s.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static final class ProviderOption {
        final String id;
        final String label;

        ProviderOption(String id, String label) {
            this.id = id;
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }
}
