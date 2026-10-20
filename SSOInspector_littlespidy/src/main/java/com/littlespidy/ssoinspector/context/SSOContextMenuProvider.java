// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.context;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.ssoinspector.engine.OAuthFlowClassifier;
import com.littlespidy.ssoinspector.engine.OAuthParameterParser;
import com.littlespidy.ssoinspector.engine.OAuthPassiveAuditEngine;
import com.littlespidy.ssoinspector.model.*;
import com.littlespidy.ssoinspector.ui.SSOMainSuiteTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class SSOContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final OAuthDataStore dataStore;
    private final SSOMainSuiteTab mainSuiteTab;

    public SSOContextMenuProvider(MontoyaApi api, OAuthDataStore dataStore, SSOMainSuiteTab mainSuiteTab) {
        this.api = api;
        this.dataStore = dataStore;
        this.mainSuiteTab = mainSuiteTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        List<HttpRequestResponse> targetRequests = new ArrayList<>(event.selectedRequestResponses());
        if (targetRequests.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
            targetRequests.add(event.messageEditorRequestResponse().get().requestResponse());
        }

        if (!targetRequests.isEmpty()) {
            JMenu ssoMenu = new JMenu("Send to SSO Inspector");

            JMenuItem sendToOAuthItem = new JMenuItem("OAuth");
            sendToOAuthItem.addActionListener(e -> {
                mainSuiteTab.selectOAuthTab();

                for (HttpRequestResponse rr : targetRequests) {
                    if (rr == null || rr.request() == null) continue;

                    int id = dataStore.nextId();
                    OAuthRequestEntry entry = new OAuthRequestEntry(id, rr);

                    List<OAuthParam> params = OAuthParameterParser.parseParameters(rr.request());
                    OAuthFlowType flow = OAuthFlowClassifier.classify(rr.request().path(), params);

                    entry.setParameters(params);
                    entry.setFlowType(flow);

                    if (mainSuiteTab.getOAuthTab().isAutoAnalyzeEnabled()) {
                        List<SSOAuditIssue> issues = OAuthPassiveAuditEngine.audit(rr, params, flow);
                        entry.setIssues(issues);
                    }

                    dataStore.addEntry(entry);
                    api.logging().logToOutput("[SSO Inspector] Added request #" + id + " (" + flow.getDisplayName() + ") to OAuth tab.");
                }
            });
            ssoMenu.add(sendToOAuthItem);
            menuItems.add(ssoMenu);
        } else {
            JMenuItem openOAuthItem = new JMenuItem("Open SSO Inspector (OAuth)");
            openOAuthItem.addActionListener(e -> mainSuiteTab.selectOAuthTab());
            menuItems.add(openOAuthItem);
        }

        return menuItems;
    }
}
