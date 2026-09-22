// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.context;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.activescansessionkeeper.config.CookieMode;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;
import com.littlespidy.activescansessionkeeper.engine.ScanSessionCoordinator;
import com.littlespidy.activescansessionkeeper.ui.ActiveScanSessionKeeperTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Context menu provider that allows testers to right-click any HTTP request in Burp
 * (Proxy History, Repeater, Logger, Scanner) to set the active scan session cookie or scope.
 *
 * @author littlespidy
 */
public class SessionKeeperContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final SessionKeeperConfig config;
    private final ScanSessionCoordinator coordinator;
    private final ActiveScanSessionKeeperTab mainTab;

    public SessionKeeperContextMenuProvider(MontoyaApi api, SessionKeeperConfig config,
                                            ScanSessionCoordinator coordinator,
                                            ActiveScanSessionKeeperTab mainTab) {
        this.api = api;
        this.config = config;
        this.coordinator = coordinator;
        this.mainTab = mainTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        List<HttpRequestResponse> targetRequests = new ArrayList<>(event.selectedRequestResponses());
        if (targetRequests.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
            targetRequests.add(event.messageEditorRequestResponse().get().requestResponse());
        }

        if (!targetRequests.isEmpty()) {
            HttpRequestResponse rr = targetRequests.get(0);
            HttpRequest req = rr.request();

            if (req != null) {
                // 1. Set as Active Scan Cookie
                JMenuItem setCookieItem = new JMenuItem("🍪 Set as Active Scan Session Cookie");
                setCookieItem.addActionListener(e -> {
                    String host = req.httpService().host();
                    String cookieHeader = req.hasHeader("Cookie") ? req.headerValue("Cookie") : "";

                    if (cookieHeader.isEmpty()) {
                        JOptionPane.showMessageDialog(null,
                                "The selected request does not have a 'Cookie:' header.",
                                "No Cookie Header", JOptionPane.WARNING_MESSAGE);
                        return;
                    }

                    mainTab.setCookieFromExternal(cookieHeader, host);
                    JOptionPane.showMessageDialog(null,
                            "Configured Session Keeper with credentials for host: " + host + "\n\nCookie:\n" + cookieHeader,
                            "Cookie Configured", JOptionPane.INFORMATION_MESSAGE);
                });
                items.add(setCookieItem);

                // 2. Set Host Filter
                JMenuItem setHostItem = new JMenuItem("🎯 Set Target Host Scope (" + req.httpService().host() + ")");
                setHostItem.addActionListener(e -> {
                    String host = req.httpService().host();
                    config.setTargetHostFilter(host);
                    JOptionPane.showMessageDialog(null,
                            "Session Keeper target host filter set to: " + host,
                            "Target Host Updated", JOptionPane.INFORMATION_MESSAGE);
                });
                items.add(setHostItem);
            }
        }

        // Pause / Resume Menu Items
        if (coordinator.isPaused()) {
            JMenuItem resumeItem = new JMenuItem("▶ Resume Active Scanner");
            resumeItem.addActionListener(e -> coordinator.resumeScan());
            items.add(resumeItem);
        } else {
            JMenuItem pauseItem = new JMenuItem("⏸ Pause Active Scanner");
            pauseItem.addActionListener(e -> coordinator.pauseScanManually());
            items.add(pauseItem);
        }

        return items;
    }
}
