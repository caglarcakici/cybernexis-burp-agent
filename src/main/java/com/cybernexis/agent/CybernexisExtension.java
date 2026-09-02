/*
 * Montoya entry point. Wires configuration, the tool registry, the model client,
 * the agent loop, and the Swing UI, then registers the Cybernexis suite tab.
 */
package com.cybernexis.agent;

import javax.swing.SwingUtilities;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.cybernexis.agent.ollama.OllamaClient;
import com.cybernexis.agent.scanner.AiPassiveScanCheck;
import com.cybernexis.agent.tools.BurpTools;
import com.cybernexis.agent.tools.MessageStore;
import com.cybernexis.agent.tools.TargetMemory;
import com.cybernexis.agent.tools.ToolContext;
import com.cybernexis.agent.tools.ToolRegistry;
import com.cybernexis.agent.ui.ChatView;
import com.cybernexis.agent.ui.ConfigPanel;
import com.cybernexis.agent.ui.MainPanel;
import com.cybernexis.agent.ui.ToolActivityLog;

public class CybernexisExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(Branding.PRODUCT);

        ConfigStore store = new ConfigStore(api.persistence().preferences());
        Config config = store.load();

        ToolRegistry registry = BurpTools.buildRegistry();
        MessageStore messageStore = new MessageStore();
        TargetMemory targetMemory = TargetMemory.load(api.persistence().preferences());
        ToolContext toolContext = new ToolContext(api, messageStore, targetMemory);
        OllamaClient client = new OllamaClient(config);

        SwingUtilities.invokeLater(() -> {
            ToolActivityLog activityLog = new ToolActivityLog(api.logging());
            ConfigPanel configPanel = new ConfigPanel(config, store);
            ChatView chatView = new ChatView(config, client, registry, toolContext, activityLog,
                    api.persistence().preferences());
            MainPanel main = new MainPanel(chatView, configPanel, activityLog);
            api.userInterface().registerSuiteTab(Branding.TAB, main);
            api.userInterface().registerContextMenuItemsProvider(new SendToAgent(chatView));
        });

        try {
            api.scanner().registerPassiveScanCheck(
                    new AiPassiveScanCheck(config, client, api),
                    ScanCheckType.PER_REQUEST);
        } catch (RuntimeException e) {
            api.logging().logToOutput(Branding.PRODUCT + " passive scan check not registered: " + e.getMessage());
        }

        api.logging().logToOutput(Branding.PRODUCT + " loaded. "
                + registry.names().size() + " tools registered. Model: " + config.model
                + ". Passive scanner: " + (config.passiveAiScan ? "ON" : "OFF"));
    }

    /** Adds a "Send to Cybernexis" item to Burp's HTTP context menus. */
    private static final class SendToAgent implements ContextMenuItemsProvider {
        private final ChatView chatView;

        SendToAgent(ChatView chatView) {
            this.chatView = chatView;
        }

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            HttpRequestResponse selected = pick(event);
            if (selected == null) {
                return null;
            }
            JMenuItem item = new JMenuItem(Branding.CONTEXT_MENU);
            item.addActionListener(e -> SwingUtilities.invokeLater(() -> chatView.newSessionForRequest(selected)));
            List<Component> items = new ArrayList<>();
            items.add(item);
            return items;
        }

        private static HttpRequestResponse pick(ContextMenuEvent event) {
            try {
                List<HttpRequestResponse> selected = event.selectedRequestResponses();
                if (selected != null && !selected.isEmpty()) {
                    return selected.get(0);
                }
                return event.messageEditorRequestResponse()
                        .map(m -> m.requestResponse())
                        .orElse(null);
            } catch (RuntimeException e) {
                return null;
            }
        }
    }
}
