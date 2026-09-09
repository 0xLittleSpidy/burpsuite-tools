// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.context;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.littlespidy.jwtcomparator.model.JWTParser;
import com.littlespidy.jwtcomparator.model.JWTTokenModel;
import com.littlespidy.jwtcomparator.ui.JWTComparatorTab;
import com.littlespidy.jwtcomparator.ui.TokenSlotsContainer;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Context menu provider enabling right-click "Send to JWT Comparator" across Burp tools.
 */
public class JWTContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final JWTComparatorTab mainTab;

    public JWTContextMenuProvider(MontoyaApi api, JWTComparatorTab mainTab) {
        this.api = api;
        this.mainTab = mainTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 1. Resolve target HttpRequest and HttpResponse
        HttpRequest request = null;
        HttpResponse response = null;
        String selectedToken = null;
        String hostLabel = "";

        if (event.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
            HttpRequestResponse rr = editor.requestResponse();
            request = rr.request();
            if (rr.hasResponse()) {
                response = rr.response();
            }

            // Check if user highlighted a JWT string
            if (editor.selectionOffsets().isPresent()) {
                Range range = editor.selectionOffsets().get();
                if (range.startIndexInclusive() < range.endIndexExclusive()) {
                    try {
                        byte[] bytes;
                        if (editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE && rr.hasResponse()) {
                            bytes = rr.response().toByteArray().getBytes();
                        } else {
                            bytes = rr.request().toByteArray().getBytes();
                        }
                        if (range.endIndexExclusive() <= bytes.length) {
                            String text = new String(bytes, range.startIndexInclusive(),
                                    range.endIndexExclusive() - range.startIndexInclusive(), StandardCharsets.UTF_8);
                            String extracted = JWTParser.extractTokenFromText(text);
                            if (extracted != null) {
                                selectedToken = extracted;
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        } else if (!event.selectedRequestResponses().isEmpty()) {
            HttpRequestResponse rr = event.selectedRequestResponses().get(0);
            request = rr.request();
            if (rr.hasResponse()) {
                response = rr.response();
            }
        }

        if (request != null && request.httpService() != null) {
            hostLabel = request.httpService().host();
        }

        // If not selected from highlighted text, attempt auto-extraction from request or response
        if (selectedToken == null) {
            if (request != null) {
                selectedToken = JWTParser.extractFromHttpRequest(request);
            }
            if (selectedToken == null && response != null) {
                selectedToken = JWTParser.extractFromHttpResponse(response);
            }
        }

        final String tokenToSend = selectedToken;
        final String domainLabel = hostLabel;

        TokenSlotsContainer slots = mainTab.getComparisonPanel().getSlotsContainer();
        List<JWTTokenModel> currentTokens = slots.getTokens();

        JMenu sendMenu = new JMenu("Send to JWT Comparator");

        if (tokenToSend == null) {
            JMenuItem noTokenItem = new JMenuItem("No JWT detected (open comparator anyway)");
            noTokenItem.addActionListener(e -> SwingUtilities.invokeLater(mainTab::selectComparatorTab));
            sendMenu.add(noTokenItem);
        } else {
            // Options for each existing slot
            for (JWTTokenModel tm : currentTokens) {
                int slotIndex = tm.getSlotIndex();
                String itemTitle = "Send to Token " + slotIndex + " (" + tm.getLabel() + ")";
                JMenuItem item = new JMenuItem(itemTitle);
                item.addActionListener(e -> SwingUtilities.invokeLater(() -> {
                    String finalLabel = tm.getLabel();
                    if (finalLabel.startsWith("Token ") || finalLabel.startsWith("Domain ")) {
                        finalLabel = domainLabel.isEmpty() ? finalLabel : domainLabel;
                    }
                    slots.loadIntoSlot(slotIndex, tokenToSend, finalLabel);
                    mainTab.selectComparatorTab();
                }));
                sendMenu.add(item);
            }

            // Option to append as a new slot
            JMenuItem newSlotItem = new JMenuItem("➕ Send as New Token (Token " + (currentTokens.size() + 1) + ")");
            newSlotItem.addActionListener(e -> SwingUtilities.invokeLater(() -> {
                String finalLabel = domainLabel.isEmpty() ? "Token " + (slots.getSlotCount() + 1) : domainLabel;
                slots.addTokenSlot(tokenToSend, finalLabel);
                mainTab.selectComparatorTab();
            }));
            sendMenu.add(newSlotItem);
        }

        menuItems.add(sendMenu);
        return menuItems;
    }
}
