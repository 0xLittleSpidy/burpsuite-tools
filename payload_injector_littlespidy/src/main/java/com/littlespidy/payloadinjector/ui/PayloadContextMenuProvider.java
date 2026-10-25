// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.littlespidy.payloadinjector.engine.ParamPayloadInjectorEngine;
import com.littlespidy.payloadinjector.engine.SmugglingInjectorEngine;
import com.littlespidy.payloadinjector.model.InjectionSettings;
import com.littlespidy.payloadinjector.model.ParamPayloadEntry;
import com.littlespidy.payloadinjector.model.ParamPayloadStore;
import com.littlespidy.payloadinjector.model.SmugglingPayloadEntry;
import com.littlespidy.payloadinjector.model.SmugglingPayloadStore;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Context menu provider supplying actions to:
 * 1. Dispatch armed parameter payloads across all categories to Repeater.
 * 2. In-place inject parameter payloads into all parameters or selected text.
 * 3. In-place inject HTTP Request Smuggling desync payloads into Repeater request editors.
 *
 * @author littlespidy
 */
public class PayloadContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final Map<String, ParamPayloadStore> paramStores;
    private final SmugglingPayloadStore smugglingStore;
    private final com.littlespidy.payloadinjector.model.FilePathStore_littlespidy linuxFilePathStore;
    private final com.littlespidy.payloadinjector.model.FilePathStore_littlespidy windowsFilePathStore;
    private final InjectionSettings settings;

    public PayloadContextMenuProvider(MontoyaApi api,
                                      Map<String, ParamPayloadStore> paramStores,
                                      SmugglingPayloadStore smugglingStore,
                                      com.littlespidy.payloadinjector.model.FilePathStore_littlespidy linuxFilePathStore,
                                      com.littlespidy.payloadinjector.model.FilePathStore_littlespidy windowsFilePathStore,
                                      InjectionSettings settings) {
        this.api = api;
        this.paramStores = (paramStores != null) ? paramStores : Collections.emptyMap();
        this.smugglingStore = smugglingStore;
        this.linuxFilePathStore = linuxFilePathStore;
        this.windowsFilePathStore = windowsFilePathStore;
        this.settings = settings;
    }

    public PayloadContextMenuProvider(MontoyaApi api,
                                      Map<String, ParamPayloadStore> paramStores,
                                      SmugglingPayloadStore smugglingStore,
                                      InjectionSettings settings) {
        this(api, paramStores, smugglingStore, null, null, settings);
    }

    public PayloadContextMenuProvider(MontoyaApi api,
                                      ParamPayloadStore xssStore,
                                      ParamPayloadStore cstiStore,
                                      ParamPayloadStore sqlStore,
                                      SmugglingPayloadStore smugglingStore,
                                      InjectionSettings settings) {
        this(api, buildLegacyMap(xssStore, cstiStore, sqlStore), smugglingStore, settings);
    }

    private static Map<String, ParamPayloadStore> buildLegacyMap(ParamPayloadStore xss,
                                                                 ParamPayloadStore csti,
                                                                 ParamPayloadStore sql) {
        Map<String, ParamPayloadStore> map = new LinkedHashMap<>();
        if (xss != null) map.put("XSS", xss);
        if (csti != null) map.put("CSTI", csti);
        if (sql != null) map.put("SQL", sql);
        return map;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        HttpRequest targetRequest = extractTargetRequest(event);
        if (targetRequest == null) {
            return menuItems;
        }

        JMenu rootMenu = new JMenu("Payload Injector (littlespidy)");

        // -- 1. Send to Repeater with Armed Payloads --
        JMenu sendToRepeaterMenu = new JMenu("Send to Repeater with Armed Payloads");
        for (Map.Entry<String, ParamPayloadStore> entry : paramStores.entrySet()) {
            String category = entry.getKey();
            ParamPayloadStore store = entry.getValue();
            populateCategorySubmenu(sendToRepeaterMenu, category, store, p -> {
                HttpRequest mutated = ParamPayloadInjectorEngine.injectAll(targetRequest, p, settings);
                String tabTitle = formatRepeaterTabTitle(targetRequest, category, p);
                api.repeater().sendToRepeater(mutated, tabTitle);
            });
        }
        rootMenu.add(sendToRepeaterMenu);

        // -- 2. Web Root Probes (Send to Repeater): PUT File Upload & Important Files --
        JMenuItem putUploadItem = new JMenuItem("Send PUT Upload Test to Repeater (" + com.littlespidy.payloadinjector.engine.RootProbeEngine_littlespidy.DEFAULT_PUT_FILENAME + ")");
        putUploadItem.addActionListener(e -> {
            HttpRequest putReq = com.littlespidy.payloadinjector.engine.RootProbeEngine_littlespidy.buildPutUploadRequest(targetRequest);
            String tabTitle = "PUT " + com.littlespidy.payloadinjector.engine.RootProbeEngine_littlespidy.DEFAULT_PUT_FILENAME + " [" + extractHostForTitle(targetRequest) + "]";
            api.repeater().sendToRepeater(putReq, tabTitle);
        });
        rootMenu.add(putUploadItem);

        JMenuItem robotsTxtItem = new JMenuItem("Send robots.txt Request to Repeater (/robots.txt)");
        robotsTxtItem.addActionListener(e -> {
            HttpRequest robotsReq = com.littlespidy.payloadinjector.engine.RootProbeEngine_littlespidy.buildRobotsTxtRequest(targetRequest);
            String tabTitle = "GET /robots.txt [" + extractHostForTitle(targetRequest) + "]";
            api.repeater().sendToRepeater(robotsReq, tabTitle);
        });
        rootMenu.add(robotsTxtItem);

        JMenu importantFilesMenu = new JMenu("Check Important Files & Directories (Send to Repeater)");
        JMenuItem subRobotsItem = new JMenuItem("robots.txt (/robots.txt)");
        subRobotsItem.addActionListener(e -> {
            HttpRequest robotsReq = com.littlespidy.payloadinjector.engine.RootProbeEngine_littlespidy.buildRobotsTxtRequest(targetRequest);
            String tabTitle = "GET /robots.txt [" + extractHostForTitle(targetRequest) + "]";
            api.repeater().sendToRepeater(robotsReq, tabTitle);
        });
        importantFilesMenu.add(subRobotsItem);
        rootMenu.add(importantFilesMenu);

        // -- 2. Editor In-Place Modifications (if in Message Editor) --
        Optional<MessageEditorHttpRequestResponse> editorOpt = event.messageEditorRequestResponse();
        if (editorOpt.isPresent()) {
            MessageEditorHttpRequestResponse editor = editorOpt.get();

            // In-place all parameters
            JMenu inPlaceAllMenu = new JMenu("Inject into All Parameters (In-Place)");
            for (Map.Entry<String, ParamPayloadStore> entry : paramStores.entrySet()) {
                String category = entry.getKey();
                ParamPayloadStore store = entry.getValue();
                populateCategorySubmenu(inPlaceAllMenu, category, store, p -> {
                    HttpRequest mutated = ParamPayloadInjectorEngine.injectAll(editor.requestResponse().request(), p, settings);
                    editor.setRequest(mutated);
                });
            }
            rootMenu.add(inPlaceAllMenu);

            // In-place selected text / range
            Optional<Range> selectionOpt = editor.selectionOffsets();
            if (selectionOpt.isPresent() && selectionOpt.get().startIndexInclusive() < selectionOpt.get().endIndexExclusive()) {
                Range selection = selectionOpt.get();
                JMenu inPlaceSelectionMenu = new JMenu("Inject into Selected Text / Range");
                for (Map.Entry<String, ParamPayloadStore> entry : paramStores.entrySet()) {
                    String category = entry.getKey();
                    ParamPayloadStore store = entry.getValue();
                    populateCategorySubmenu(inPlaceSelectionMenu, category, store, p -> {
                        HttpRequest mutated = ParamPayloadInjectorEngine.injectSelection(editor.requestResponse().request(), selection, p, settings);
                        editor.setRequest(mutated);
                    });
                }
                rootMenu.add(inPlaceSelectionMenu);
            }

            // -- 3. HTTP Request Smuggling Injection --
            if (smugglingStore != null) {
                JMenu smugglingMenu = new JMenu("HTTP Request Smuggling");
                List<SmugglingPayloadEntry> smugglingEntries = smugglingStore.getEntries();
                if (smugglingEntries.isEmpty()) {
                    JMenuItem noItem = new JMenuItem("No payloads loaded in http_request_smuggling_payloads.json");
                    noItem.setEnabled(false);
                    smugglingMenu.add(noItem);
                } else {
                    for (SmugglingPayloadEntry smg : smugglingEntries) {
                        JMenuItem item = new JMenuItem(smg.getName());
                        if (!smg.getDescription().isEmpty()) {
                            item.setToolTipText(smg.getDescription());
                        }
                        item.addActionListener(e -> {
                            HttpRequest mutated = SmugglingInjectorEngine.applyPayload(editor.requestResponse().request(), smg);
                            editor.setRequest(mutated);
                        });
                        smugglingMenu.add(item);
                    }
                }
                rootMenu.add(smugglingMenu);
            }

            // -- 4. Target File Path Substitution (<FILE_PATH>) --
            if (linuxFilePathStore != null || windowsFilePathStore != null) {
                JMenu filePathMenu = new JMenu("Replace Target File Path (<FILE_PATH>)");

                if (linuxFilePathStore != null) {
                    populateFilePathSubmenu(filePathMenu, "Linux File Paths", linuxFilePathStore, fp -> {
                        HttpRequest mutated = ParamPayloadInjectorEngine.replaceFilePathPlaceholder(
                                editor.requestResponse().request(), fp.getPath(), editor.selectionOffsets());
                        editor.setRequest(mutated);
                    });
                }

                if (windowsFilePathStore != null) {
                    populateFilePathSubmenu(filePathMenu, "Windows File Paths", windowsFilePathStore, fp -> {
                        HttpRequest mutated = ParamPayloadInjectorEngine.replaceFilePathPlaceholder(
                                editor.requestResponse().request(), fp.getPath(), editor.selectionOffsets());
                        editor.setRequest(mutated);
                    });
                }

                rootMenu.add(filePathMenu);
            }
        }

        menuItems.add(rootMenu);
        return menuItems;
    }

    private void populateFilePathSubmenu(JMenu parentMenu, String title, com.littlespidy.payloadinjector.model.FilePathStore_littlespidy store, java.util.function.Consumer<com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy> onSelect) {
        List<com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy> entries = store.getEntries();
        if (entries.isEmpty()) return;

        JMenu menu = new JMenu(title);
        Map<String, List<com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy>> grouped = new LinkedHashMap<>();
        for (var e : entries) {
            String cat = (e.getCategory() != null && !e.getCategory().isBlank()) ? e.getCategory() : "General";
            grouped.computeIfAbsent(cat, k -> new ArrayList<>()).add(e);
        }

        for (Map.Entry<String, List<com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy>> group : grouped.entrySet()) {
            JMenu catSubmenu = new JMenu(group.getKey());
            for (var entry : group.getValue()) {
                JMenuItem item = new JMenuItem(entry.getPath());
                if (!entry.getDescription().isEmpty()) {
                    item.setToolTipText(entry.getDescription());
                }
                item.addActionListener(e -> onSelect.accept(entry));
                catSubmenu.add(item);
            }
            menu.add(catSubmenu);
        }

        parentMenu.add(menu);
    }

    private void populateCategorySubmenu(JMenu parentMenu, String categoryName, ParamPayloadStore store, java.util.function.Consumer<ParamPayloadEntry> onSelect) {
        List<ParamPayloadEntry> list = store.getEntries();
        if (list.isEmpty()) {
            return;
        }

        JMenu catMenu = new JMenu(categoryName + " Payloads");

        if (categoryName.equalsIgnoreCase("Path Traversal")) {
            JMenu windowsMenu = new JMenu("Windows");
            JMenu linuxMenu = new JMenu("Linux");

            for (ParamPayloadEntry entry : list) {
                JMenuItem item = new JMenuItem(entry.getName() + " (" + truncate(entry.getTemplate(), 30) + ")");
                if (!entry.getDescription().isEmpty()) {
                    item.setToolTipText(entry.getDescription());
                }
                item.addActionListener(e -> onSelect.accept(entry));

                if ("Windows".equalsIgnoreCase(entry.getPlatform())) {
                    windowsMenu.add(item);
                } else {
                    linuxMenu.add(item);
                }
            }

            if (windowsMenu.getItemCount() > 0) {
                catMenu.add(windowsMenu);
            }
            if (linuxMenu.getItemCount() > 0) {
                catMenu.add(linuxMenu);
            }
        } else {
            for (ParamPayloadEntry entry : list) {
                JMenuItem item = new JMenuItem(entry.getName() + " (" + truncate(entry.getTemplate(), 30) + ")");
                if (!entry.getDescription().isEmpty()) {
                    item.setToolTipText(entry.getDescription());
                }
                item.addActionListener(e -> onSelect.accept(entry));
                catMenu.add(item);
            }
        }
        parentMenu.add(catMenu);
    }

    private String formatRepeaterTabTitle(HttpRequest request, String category, ParamPayloadEntry entry) {
        String method = (request != null && request.method() != null && !request.method().isBlank())
                ? request.method() : "REQ";

        String path = "/";
        if (request != null) {
            String rawPath = request.pathWithoutQuery();
            if (rawPath == null || rawPath.isBlank()) {
                rawPath = request.path();
                if (rawPath != null && rawPath.contains("?")) {
                    rawPath = rawPath.substring(0, rawPath.indexOf('?'));
                }
            }
            if (rawPath != null && !rawPath.isBlank()) {
                path = rawPath;
            }
        }

        if (path.length() > 20) {
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash > 0 && (path.length() - lastSlash) <= 16) {
                path = "..." + path.substring(lastSlash);
            } else {
                path = path.substring(0, 17) + "...";
            }
        }

        return String.format("%s %s [%s: %s]", method, path, category, entry.getName());
    }

    private String extractHostForTitle(HttpRequest request) {
        if (request != null) {
            String host = request.headerValue("Host");
            if (host != null && !host.isBlank()) {
                return host.trim();
            }
            if (request.httpService() != null && request.httpService().host() != null) {
                return request.httpService().host();
            }
        }
        return "Target";
    }

    private HttpRequest extractTargetRequest(ContextMenuEvent event) {
        if (event == null) {
            return null;
        }
        try {
            Optional<MessageEditorHttpRequestResponse> editorOpt = event.messageEditorRequestResponse();
            if (editorOpt.isPresent()) {
                MessageEditorHttpRequestResponse editor = editorOpt.get();
                if (editor.requestResponse() != null && editor.requestResponse().request() != null) {
                    return editor.requestResponse().request();
                }
            }
        } catch (Exception ignored) {
        }
        try {
            List<burp.api.montoya.http.message.HttpRequestResponse> selected = event.selectedRequestResponses();
            if (selected != null && !selected.isEmpty()) {
                var rr = selected.get(0);
                if (rr != null && rr.request() != null) {
                    return rr.request();
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static String truncate(String str, int max) {
        if (str == null || str.length() <= max) return str;
        return str.substring(0, max) + "...";
    }
}
