// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ContextMenuProvider_littlespidy implements ContextMenuItemsProvider {
    private final GraphQLCopRootTab_littlespidy rootTab;

    public ContextMenuProvider_littlespidy(GraphQLCopRootTab_littlespidy rootTab) {
        this.rootTab = rootTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) {
            return Collections.emptyList();
        }

        JMenuItem menuItem = new JMenuItem("Send to graphql");
        menuItem.addActionListener(e -> {
            HttpRequestResponse pair = selected.get(0);
            HttpRequest req = pair.request();
            if (req != null) {
                String url = req.url();
                StringBuilder headers = new StringBuilder();
                for (burp.api.montoya.http.message.HttpHeader h : req.headers()) {
                    String name = h.name().toLowerCase();
                    if (name.equals("authorization") || name.equals("cookie") || name.startsWith("x-") || name.equals("apikey")) {
                        headers.append(h.name()).append(": ").append(h.value()).append("\n");
                    }
                }
                String title = req.path();
                if (title == null || title.isEmpty() || title.equals("/")) {
                    title = "Target";
                }
                rootTab.addNewEndpointTab(title, url, headers.toString().trim());
            }
        });

        List<Component> items = new ArrayList<>();
        items.add(menuItem);
        return items;
    }
}
