// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Context menu provider that allows testers to send any HTTP request from Proxy,
 * Repeater, Target, or Logger directly into the ResAPI Version Finder tab.
 */
public class APIInspectorContextMenu_littlespidy implements ContextMenuItemsProvider {

    private final ResAPIVersionFinderTab_littlespidy versionFinderTab;

    public APIInspectorContextMenu_littlespidy(ResAPIVersionFinderTab_littlespidy versionFinderTab) {
        this.versionFinderTab = versionFinderTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuList = new ArrayList<>();

        List<HttpRequestResponse> targets = new ArrayList<>();
        if (event.messageEditorRequestResponse().isPresent()) {
            targets.add(event.messageEditorRequestResponse().get().requestResponse());
        }
        if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty()) {
            for (HttpRequestResponse rr : event.selectedRequestResponses()) {
                if (!targets.contains(rr)) {
                    targets.add(rr);
                }
            }
        }

        if (targets.isEmpty()) {
            return menuList;
        }

        JMenuItem sendItem = new JMenuItem("Send to API Inspector (ResAPI Version Finder)");
        sendItem.addActionListener(e -> {
            for (HttpRequestResponse target : targets) {
                if (target.request() != null) {
                    versionFinderTab.addNewSession(
                            target.request(),
                            target.hasResponse() ? target.response() : null
                    );
                }
            }
        });

        menuList.add(sendItem);
        return menuList;
    }
}
