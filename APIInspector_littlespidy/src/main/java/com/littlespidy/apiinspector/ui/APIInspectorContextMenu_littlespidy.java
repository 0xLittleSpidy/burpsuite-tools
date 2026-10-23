// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.apiinspector.intruder.AuthStripper_littlespidy;
import com.littlespidy.apiinspector.intruder.PathVariationGenerator_littlespidy;
import com.littlespidy.apiinspector.model.IntruderStrategyEntry_littlespidy.GeneratedVariationItem;
import com.littlespidy.apiinspector.model.IntruderStrategyEntry_littlespidy.ReferenceRequestEntry;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Context menu provider that allows testers to trigger API Inspector tools directly from
 * Proxy HTTP history, Repeater, Target site map, or Logger:
 * - Send to ResAPI Version Finder
 * - API Documentation Intruder Strategy
 * - API Endpoint Discovery Intruder Strategy
 */
public class APIInspectorContextMenu_littlespidy implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final APIInspectorTab_littlespidy rootTab;
    private final AtomicInteger referenceIdCounter = new AtomicInteger(1);

    public APIInspectorContextMenu_littlespidy(MontoyaApi api, APIInspectorTab_littlespidy rootTab) {
        this.api = api;
        this.rootTab = rootTab;
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

        // Direct Top-Level Action: Send to ResAPI Version Finder
        JMenuItem directVersionFinderItem = new JMenuItem("Send to ResAPI Version Finder");
        directVersionFinderItem.addActionListener(e -> {
            for (HttpRequestResponse target : targets) {
                if (target.request() != null) {
                    rootTab.getVersionFinderTab().addNewSession(
                            target.request(),
                            target.hasResponse() ? target.response() : null
                    );
                }
            }
            rootTab.selectTab(rootTab.getVersionFinderTab());
        });
        menuList.add(directVersionFinderItem);

        JMenu apiInspectorMenu = new JMenu("API Inspector (littlespidy)");

        // Action 1: Send to ResAPI Version Finder
        JMenuItem versionFinderItem = new JMenuItem("Send to ResAPI Version Finder");
        versionFinderItem.addActionListener(e -> {
            for (HttpRequestResponse target : targets) {
                if (target.request() != null) {
                    rootTab.getVersionFinderTab().addNewSession(
                            target.request(),
                            target.hasResponse() ? target.response() : null
                    );
                }
            }
            rootTab.selectTab(rootTab.getVersionFinderTab());
        });
        apiInspectorMenu.add(versionFinderItem);

        apiInspectorMenu.addSeparator();

        // Action 2: API Documentation Intruder Strategy
        JMenuItem docStrategyItem = new JMenuItem("API Documentation Intruder Strategy");
        docStrategyItem.setToolTipText("Progressively remove trailing path segments and send authenticated/unauthenticated variants to Intruder");
        docStrategyItem.addActionListener(e -> {
            for (HttpRequestResponse target : targets) {
                if (target.request() != null) {
                    executeStrategy(target.request(), true);
                }
            }
            rootTab.selectTab(rootTab.getDocStrategyTab());
        });
        apiInspectorMenu.add(docStrategyItem);

        // Action 3: API Endpoint Discovery Intruder Strategy
        JMenuItem endpointDiscoveryItem = new JMenuItem("API Endpoint Discovery Intruder Strategy");
        endpointDiscoveryItem.setToolTipText("Progressively remove prefix and segment variations and send authenticated/unauthenticated variants to Intruder");
        endpointDiscoveryItem.addActionListener(e -> {
            for (HttpRequestResponse target : targets) {
                if (target.request() != null) {
                    executeStrategy(target.request(), false);
                }
            }
            rootTab.selectTab(rootTab.getEndpointDiscoveryTab());
        });
        apiInspectorMenu.add(endpointDiscoveryItem);

        menuList.add(apiInspectorMenu);
        return menuList;
    }

    private void executeStrategy(HttpRequest originalRequest, boolean isDocStrategy) {
        String originalPath = originalRequest.path();
        List<String> pathVariations = isDocStrategy
                ? PathVariationGenerator_littlespidy.generateDocumentationPaths(originalPath)
                : PathVariationGenerator_littlespidy.generateEndpointDiscoveryPaths(originalPath);

        if (pathVariations.isEmpty()) {
            // If already root path "/", at least include root
            pathVariations = List.of("/");
        }

        HttpRequest unauthBaseReq = AuthStripper_littlespidy.stripAuthentication(originalRequest);
        List<GeneratedVariationItem> variationItems = new ArrayList<>();
        int varIndex = 1;

        for (String pathVar : pathVariations) {
            // 1. Authenticated Variant
            HttpRequest authReq = originalRequest.withPath(pathVar);
            if (api != null && api.intruder() != null) {
                api.intruder().sendToIntruder(authReq);
            }
            variationItems.add(new GeneratedVariationItem(
                    varIndex++,
                    pathVar,
                    true,
                    "Sent to Intruder",
                    authReq.url() != null ? authReq.url() : pathVar,
                    authReq
            ));

            // 2. Unauthenticated Variant
            HttpRequest unauthReq = unauthBaseReq.withPath(pathVar);
            if (api != null && api.intruder() != null) {
                api.intruder().sendToIntruder(unauthReq);
            }
            variationItems.add(new GeneratedVariationItem(
                    varIndex++,
                    pathVar,
                    false,
                    "Sent to Intruder",
                    unauthReq.url() != null ? unauthReq.url() : pathVar,
                    unauthReq
            ));
        }

        int refId = referenceIdCounter.getAndIncrement();
        String host = (originalRequest.httpService() != null && originalRequest.httpService().host() != null)
                ? originalRequest.httpService().host() : "unknown";
        String method = originalRequest.method() != null ? originalRequest.method() : "GET";
        String strategyName = isDocStrategy ? "API Documentation" : "API Endpoint Discovery";

        ReferenceRequestEntry refEntry = new ReferenceRequestEntry(
                refId,
                System.currentTimeMillis(),
                strategyName,
                method,
                originalPath,
                host,
                originalRequest.url() != null ? originalRequest.url() : originalPath,
                originalRequest,
                variationItems
        );

        if (isDocStrategy) {
            rootTab.getDocStrategyTab().addReferenceEntry(refEntry);
        } else {
            rootTab.getEndpointDiscoveryTab().addReferenceEntry(refEntry);
        }
    }
}
