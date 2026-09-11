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
            api.repeater().sendToRepeater(mutated, template.getCategory() + ": " + template.getName());
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
        List<PayloadTemplate> xssTemplates = config.getTemplatesForCategory("XSS");
        List<PayloadTemplate> angularTemplates = config.getTemplatesForCategory("Angular CSTI");
        List<PayloadTemplate> customTemplates = config.getTemplatesForCategory("Custom");

        if (!xssTemplates.isEmpty()) {
            JMenu xssMenu = new JMenu("XSS Payloads");
            for (PayloadTemplate t : xssTemplates) {
                if (t.isEnabled()) {
                    JMenuItem item = new JMenuItem(t.getName() + " (" + truncate(t.getTemplate(), 30) + ")");
                    item.addActionListener(e -> onSelect.accept(t));
                    xssMenu.add(item);
                }
            }
            parentMenu.add(xssMenu);
        }

        if (!angularTemplates.isEmpty()) {
            JMenu angularMenu = new JMenu("Angular CSTI Payloads");
            for (PayloadTemplate t : angularTemplates) {
                if (t.isEnabled()) {
                    JMenuItem item = new JMenuItem(t.getName() + " (" + truncate(t.getTemplate(), 30) + ")");
                    item.addActionListener(e -> onSelect.accept(t));
                    angularMenu.add(item);
                }
            }
            parentMenu.add(angularMenu);
        }

        if (!customTemplates.isEmpty()) {
            JMenu customMenu = new JMenu("Custom Payloads");
            for (PayloadTemplate t : customTemplates) {
                if (t.isEnabled()) {
                    JMenuItem item = new JMenuItem(t.getName() + " (" + truncate(t.getTemplate(), 30) + ")");
                    item.addActionListener(e -> onSelect.accept(t));
                    customMenu.add(item);
                }
            }
            parentMenu.add(customMenu);
        }
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
