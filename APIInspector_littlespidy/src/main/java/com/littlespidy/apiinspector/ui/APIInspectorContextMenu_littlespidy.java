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

        // Action 2: Send to Hidden API Storage
        JMenuItem hiddenStorageItem = new JMenuItem("Send to Hidden API Storage");
        hiddenStorageItem.addActionListener(e -> {
            String toolSource = resolveSourceTool(event);
            for (HttpRequestResponse target : targets) {
                if (target.request() != null) {
                    rootTab.getHiddenApiStorageTab().addEndpointFromBurpTool(target, toolSource);
                }
            }
            rootTab.selectTab(rootTab.getHiddenApiStorageTab());
        });
        apiInspectorMenu.add(hiddenStorageItem);

        apiInspectorMenu.addSeparator();

        // Action 3: Send to CORS Tester
        JMenuItem corsItem = new JMenuItem("Send to CORS Tester");
        corsItem.addActionListener(e -> {
            for (HttpRequestResponse target : targets) {
                if (target.request() != null) {
                    rootTab.getCorsTab().sendToCors(target.request(), target.hasResponse() ? target.response() : null);
                }
            }
            rootTab.selectTab(rootTab.getCorsTab());
        });
        apiInspectorMenu.add(corsItem);

        // Action 4: Send to Input Validation Fuzzer
        JMenuItem fuzzItem = new JMenuItem("Send to Input Validation Fuzzer");
        fuzzItem.addActionListener(e -> {
            for (HttpRequestResponse target : targets) {
                if (target.request() != null) {
                    rootTab.getInputValidationTab().sendToInputValidation(target.request(), target.hasResponse() ? target.response() : null);
                }
            }
            rootTab.selectTab(rootTab.getInputValidationTab());
        });
        apiInspectorMenu.add(fuzzItem);

        // Action 5: Send to POST to GET Tester
        JMenuItem postToGetItem = new JMenuItem("Send to POST to GET Tester");
        postToGetItem.addActionListener(e -> {
            for (HttpRequestResponse target : targets) {
                if (target.request() != null) {
                    rootTab.getPostToGetTab().sendToPostToGet(target.request(), target.hasResponse() ? target.response() : null);
                }
            }
            rootTab.selectTab(rootTab.getPostToGetTab());
        });
        apiInspectorMenu.add(postToGetItem);

        apiInspectorMenu.addSeparator();

        // Action 5: API Documentation Intruder Strategy
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

        // Action 4: API Endpoint Discovery Intruder Strategy
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
        HttpRequest baseRequest = originalRequest;
        if (!isDocStrategy) {
            // Strip any GET / query parameters for Endpoint Discovery
            String cleanPath = PathVariationGenerator_littlespidy.extractPathOnly(originalRequest.path());
            baseRequest = originalRequest.withPath(cleanPath);
        }

        String strategyPath = baseRequest.path();
        List<String> pathVariations = isDocStrategy
                ? PathVariationGenerator_littlespidy.generateDocumentationPaths(strategyPath)
                : PathVariationGenerator_littlespidy.generateEndpointDiscoveryPaths(strategyPath);

        if (pathVariations.isEmpty()) {
            // If already root path "/", at least include root
            pathVariations = List.of("/");
        }

        HttpRequest unauthBaseReq = AuthStripper_littlespidy.stripAuthentication(baseRequest);
        List<GeneratedVariationItem> variationItems = new ArrayList<>();
        int varIndex = 1;

        String host = (baseRequest.httpService() != null && baseRequest.httpService().host() != null)
                ? baseRequest.httpService().host() : "unknown";

        for (String pathVar : pathVariations) {
            // 1. Authenticated Variant
            HttpRequest authReq = baseRequest.withPath(pathVar);
            if (api != null && api.intruder() != null) {
                if (!isDocStrategy) {
                    String authTabTitle = "Auth - " + pathVar + " - " + host;
                    api.intruder().sendToIntruder(authReq, authTabTitle);
                } else {
                    api.intruder().sendToIntruder(authReq);
                }
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
                if (!isDocStrategy) {
                    String unauthTabTitle = "No Auth - " + pathVar + " - " + host;
                    api.intruder().sendToIntruder(unauthReq, unauthTabTitle);
                } else {
                    api.intruder().sendToIntruder(unauthReq);
                }
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
        String method = baseRequest.method() != null ? baseRequest.method() : "GET";
        String strategyName = isDocStrategy ? "API Documentation" : "API Endpoint Discovery";

        ReferenceRequestEntry refEntry = new ReferenceRequestEntry(
                refId,
                System.currentTimeMillis(),
                strategyName,
                method,
                strategyPath,
                host,
                baseRequest.url() != null ? baseRequest.url() : strategyPath,
                baseRequest,
                variationItems
        );

        if (isDocStrategy) {
            rootTab.getDocStrategyTab().addReferenceEntry(refEntry);
        } else {
            rootTab.getEndpointDiscoveryTab().addReferenceEntry(refEntry);
        }
    }

    private String resolveSourceTool(ContextMenuEvent event) {
        if (event == null || event.invocationType() == null) {
            return "Proxy History";
        }
        String typeStr = event.invocationType().toString().toLowerCase();
        if (typeStr.contains("proxy")) {
            return "Proxy History";
        } else if (typeStr.contains("repeater") || typeStr.contains("message_editor")) {
            return "Repeater";
        } else if (typeStr.contains("target") || typeStr.contains("site_map")) {
            return "Target Site Map";
        } else if (typeStr.contains("logger")) {
            return "Logger";
        }
        return "Proxy History";
    }
}
