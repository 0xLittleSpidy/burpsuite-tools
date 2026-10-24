// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.menu;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.wayback.ui.WaybackTab_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class WaybackContextMenu_littlespidy implements ContextMenuItemsProvider {

    private final WaybackTab_littlespidy waybackTab;

    public WaybackContextMenu_littlespidy(WaybackTab_littlespidy waybackTab) {
        this.waybackTab = waybackTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        if (event.isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.TARGET, ToolType.LOGGER)) {
            String domain = extractDomainFromEvent(event);
            if (domain != null && !domain.isBlank()) {
                JMenuItem sendToWayback = new JMenuItem("Send Domain (" + domain + ") to wayback");
                sendToWayback.addActionListener(e -> {
                    if (waybackTab != null) {
                        waybackTab.addDomainTab(domain);
                    }
                });
                items.add(sendToWayback);
            }
        }

        return items;
    }

    private String extractDomainFromEvent(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequestResponse m = event.messageEditorRequestResponse().get().requestResponse();
            if (m != null && m.request() != null && m.request().httpService() != null) {
                return m.request().httpService().host();
            }
        }

        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected != null && !selected.isEmpty()) {
            HttpRequestResponse m = selected.get(0);
            if (m != null && m.request() != null && m.request().httpService() != null) {
                return m.request().httpService().host();
            }
        }

        return null;
    }
}
