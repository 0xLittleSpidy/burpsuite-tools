// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.requestsmugglinginspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.littlespidy.requestsmugglinginspector.model.PayloadEntry;
import com.littlespidy.requestsmugglinginspector.model.PayloadStore;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Provides the "Request Smuggling Inspector (littlespidy)" right-click context
 * menu inside Repeater's request editor.
 *
 * <p>All menu items are loaded dynamically from {@link PayloadStore} (which reads
 * {@code smuggling-payloads.json} from disk). There are no hardcoded payloads in
 * this class - add, remove, or edit payloads by editing the JSON file and clicking
 * "Reload from JSON" in the Smuggling Payloads tab.
 *
 * <p>The menu is only shown when the right-click occurs inside a Message Editor
 * (e.g. Repeater request panel). It does not appear in table-based contexts such
 * as Proxy History row selections.
 *
 * @author littlespidy
 */
public class SmugglingContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final PayloadStore store;

    public SmugglingContextMenuProvider(MontoyaApi api, PayloadStore store) {
        this.api   = api;
        this.store = store;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        // Only render the menu when the user right-clicks inside a Message Editor
        // (Repeater request panel). Empty = no editor context -> menu stays hidden.
        Optional<MessageEditorHttpRequestResponse> editorOpt = event.messageEditorRequestResponse();
        if (editorOpt.isEmpty()) {
            return items;
        }

        JMenu rootMenu = new JMenu("Request Smuggling Inspector (littlespidy)");

        List<PayloadEntry> entries = store.getEntries();

        if (entries.isEmpty()) {
            // Graceful degradation: inform the user that no payloads are available
            JMenuItem noPayloads = new JMenuItem(
                    "No payloads loaded - check smuggling-payloads.json");
            noPayloads.setEnabled(false);
            rootMenu.add(noPayloads);
        } else {
            for (PayloadEntry entry : entries) {
                JMenuItem item = new JMenuItem(entry.getName());

                if (!entry.getDescription().isEmpty()) {
                    item.setToolTipText(entry.getDescription());
                }

                item.addActionListener(e -> {
                    MessageEditorHttpRequestResponse editor = editorOpt.get();
                    HttpRequest mutated = applyPayload(
                            editor.requestResponse().request(), entry);
                    editor.setRequest(mutated);
                });

                rootMenu.add(item);
            }
        }

        items.add(rootMenu);
        return items;
    }

    // -- Private helpers --------------------------------------------------------

    /**
     * Applies a {@link PayloadEntry} to the given request:
     *
     * <ol>
     *   <li>Replaces the body with the decoded payload body (literal {@code \r\n}
     *       escape sequences become real CR+LF bytes).</li>
     *   <li>Sets or updates every header defined in the payload entry.
     *       Headers already present are updated; absent headers are added.</li>
     * </ol>
     *
     * <p><strong>Note:</strong> {@code withBody(String)} automatically updates
     * {@code Content-Length} to the byte count of the new body. The payload
     * entry's {@code Content-Length} header value is then applied <em>after</em>
     * the body replacement so the deliberate discrepancy (the smuggling condition)
     * is preserved.
     *
     * @param request the original request from the editor
     * @param entry   the payload to apply
     * @return the mutated request ready for in-place injection
     */
    private HttpRequest applyPayload(HttpRequest request, PayloadEntry entry) {
        // Step 1: replace body - withBody(String) auto-updates Content-Length
        HttpRequest mutated = request.withBody(entry.getDecodedBody());

        // Step 2: set / update every header declared in the payload entry.
        //         MUST be done after withBody() so the deliberate Content-Length
        //         discrepancy is not overwritten by the auto-update in step 1.
        for (var header : entry.getHeaders().entrySet()) {
            mutated = mutated.hasHeader(header.getKey())
                    ? mutated.withUpdatedHeader(header.getKey(), header.getValue())
                    : mutated.withAddedHeader(header.getKey(), header.getValue());
        }

        return mutated;
    }
}
