// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.ssrfmap.engine.CollaboratorManager_littlespidy;
import burp.ssrfmap.ui.SSRFmapMainTab_littlespidy;
import java.awt.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.JMenuItem;

public class SSRFmapExtension_littlespidy implements BurpExtension, ContextMenuItemsProvider {
    private MontoyaApi api;
    private SSRFmapMainTab_littlespidy mainTab;
    private CollaboratorManager_littlespidy collaboratorManager;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("SSRFmap - SSRF Automation and Testing [littlespidy]");

        // Initialize Collaborator safely
        CollaboratorClient collabClient = null;
        try {
            collabClient = api.collaborator().createClient();
        } catch (Exception e) {
            api.logging().logToError("Collaborator initialization notice: " + e.getMessage());
        }
        collaboratorManager = new CollaboratorManager_littlespidy(collabClient);

        // Build Main UI Tab
        mainTab = new SSRFmapMainTab_littlespidy(api, collaboratorManager);
        api.userInterface().registerSuiteTab("SSRFmap", mainTab);

        // Register Context Menu
        api.userInterface().registerContextMenuItemsProvider(this);

        api.logging().logToOutput("SSRFmap [littlespidy] extension loaded successfully.");
        api.logging().logToOutput("Montoya API standard version initialized.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuList = new ArrayList<>();

        JMenuItem sendToSSRFmapItem = new JMenuItem("Send to SSRFmap");
        sendToSSRFmapItem.addActionListener(e -> {
            HttpRequestResponse targetReqResp = null;

            if (event.messageEditorRequestResponse().isPresent()) {
                MessageEditorHttpRequestResponse editorReqResp = event.messageEditorRequestResponse().get();
                targetReqResp = editorReqResp.requestResponse();
            } else if (!event.selectedRequestResponses().isEmpty()) {
                targetReqResp = event.selectedRequestResponses().get(0);
            }

            if (targetReqResp != null && mainTab != null) {
                mainTab.addNewSession(targetReqResp);
            }
        });

        menuList.add(sendToSSRFmapItem);
        return menuList;
    }
}
