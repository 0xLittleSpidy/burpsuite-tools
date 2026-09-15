package com.littlespidy.parampayloadinjector.ui;

import com.littlespidy.parampayloadinjector.engine.PayloadInjector;
import com.littlespidy.parampayloadinjector.model.InjectionConfig;
import com.littlespidy.parampayloadinjector.model.PayloadTemplate;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Context menu provider supplying actions to inject parameter-attributed payloads
 * into the current editor or dispatch armed requests to Repeater.
 */
public class ContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final InjectionConfig config;

    public ContextMenuProvider(MontoyaApi api, InjectionConfig config) {
        this.api = api;
        this.config = config;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        HttpRequest targetRequest = extractTargetRequest(event);
        if (targetRequest == null) {
            return menuItems;
        }

        JMenu rootMenu = new JMenu("Param Payload Injector (littlespidy)");

        // ── 1. Send to Repeater with Armed Payloads ──
        JMenu sendToRepeaterMenu = new JMenu("Send to Repeater with Armed Payloads");
        populateTemplateSubmenu(sendToRepeaterMenu, template -> {
            HttpRequest mutated = PayloadInjector.injectAll(targetRequest, template, config);
            String tabTitle = formatRepeaterTabTitle(targetRequest, template);
            api.repeater().sendToRepeater(mutated, tabTitle);
        });
        rootMenu.add(sendToRepeaterMenu);

        // ── 2. Editor In-Place Modifications (if in Message Editor) ──
        Optional<MessageEditorHttpRequestResponse> editorOpt = event.messageEditorRequestResponse();
        if (editorOpt.isPresent()) {
            MessageEditorHttpRequestResponse editor = editorOpt.get();

            // In-place all parameters
            JMenu inPlaceAllMenu = new JMenu("Inject into All Parameters (In-Place)");
            populateTemplateSubmenu(inPlaceAllMenu, template -> {
                HttpRequest mutated = PayloadInjector.injectAll(editor.requestResponse().request(), template, config);
                editor.setRequest(mutated);
            });
            rootMenu.add(inPlaceAllMenu);

            // In-place selected text / range
            Optional<Range> selectionOpt = editor.selectionOffsets();
            if (selectionOpt.isPresent() && selectionOpt.get().startIndexInclusive() < selectionOpt.get().endIndexExclusive()) {
                Range selection = selectionOpt.get();
                JMenu inPlaceSelectionMenu = new JMenu("Inject into Selected Text / Range");
                populateTemplateSubmenu(inPlaceSelectionMenu, template -> {
                    HttpRequest mutated = PayloadInjector.injectSelection(editor.requestResponse().request(), selection, template, config);
                    editor.setRequest(mutated);
                });
                rootMenu.add(inPlaceSelectionMenu);
            }
        }

        menuItems.add(rootMenu);
        return menuItems;
    }

    private void populateTemplateSubmenu(JMenu parentMenu, java.util.function.Consumer<PayloadTemplate> onSelect) {
        java.util.Set<String> categories = new java.util.LinkedHashSet<>();
        for (PayloadTemplate t : config.getTemplates()) {
            if (t.getCategory() != null && !t.getCategory().isBlank()) {
                categories.add(t.getCategory());
            }
        }

        for (String cat : categories) {
            List<PayloadTemplate> templates = config.getTemplatesForCategory(cat);
            List<PayloadTemplate> enabled = templates.stream().filter(PayloadTemplate::isEnabled).toList();
            if (!enabled.isEmpty()) {
                JMenu catMenu = new JMenu(cat + " Payloads");
                for (PayloadTemplate t : enabled) {
                    JMenuItem item = new JMenuItem(t.getName() + " (" + truncate(t.getTemplate(), 30) + ")");
                    item.addActionListener(e -> onSelect.accept(t));
                    catMenu.add(item);
                }
                parentMenu.add(catMenu);
            }
        }
    }

    private String formatRepeaterTabTitle(HttpRequest request, PayloadTemplate template) {
        String method = (request != null && request.method() != null && !request.method().isBlank())
                ? request.method()
                : "REQ";

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

        // Smart truncate path if it exceeds 22 chars to keep Repeater tab title compact
        if (path.length() > 22) {
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash > 0 && (path.length() - lastSlash) <= 18) {
                path = "..." + path.substring(lastSlash);
            } else {
                path = path.substring(0, 19) + "...";
            }
        }

        return String.format("%s %s [%s: %s]", method, path, template.getCategory(), template.getName());
    }

    private HttpRequest extractTargetRequest(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return event.messageEditorRequestResponse().get().requestResponse().request();
        }
        if (!event.selectedRequestResponses().isEmpty()) {
            return event.selectedRequestResponses().get(0).request();
        }
        return null;
    }

    private String truncate(String str, int max) {
        if (str == null || str.length() <= max) return str;
        return str.substring(0, max) + "...";
    }
}
