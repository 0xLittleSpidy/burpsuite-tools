// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.menu;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.quickhelper.model.ExtractionOptions_littlespidy;
import com.littlespidy.quickhelper.service.DomainExtractorService_littlespidy;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.Collections;
import java.util.List;

/**
 * Context menu provider for Quick Helper actions.
 */
public class QuickHelperContextMenu_littlespidy implements ContextMenuItemsProvider {

    private final DomainExtractorService_littlespidy extractorService;

    public QuickHelperContextMenu_littlespidy(DomainExtractorService_littlespidy extractorService) {
        this.extractorService = extractorService;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        JMenu menu = new JMenu("Quick Helper");

        JMenuItem copyAllDomainsItem = new JMenuItem("Copy All Domain Names");
        copyAllDomainsItem.addActionListener(e ->
                extractorService.extractAndCopyAsync(
                        ExtractionOptions_littlespidy.allDomains(),
                        "Copy All Domain Names"
                )
        );
        menu.add(copyAllDomainsItem);

        JMenuItem copyAllDomainsWithSchemaItem = new JMenuItem("Copy All Domain Names with HTTP Schema");
        copyAllDomainsWithSchemaItem.addActionListener(e ->
                extractorService.extractAndCopyAsync(
                        ExtractionOptions_littlespidy.allDomainsWithSchema(),
                        "Copy All Domain Names with HTTP Schema"
                )
        );
        menu.add(copyAllDomainsWithSchemaItem);

        menu.addSeparator();

        JMenuItem copyInScopeDomainsItem = new JMenuItem("Copy In-Scope Domain Names");
        copyInScopeDomainsItem.addActionListener(e ->
                extractorService.extractAndCopyAsync(
                        ExtractionOptions_littlespidy.inScopeDomains(),
                        "Copy In-Scope Domain Names"
                )
        );
        menu.add(copyInScopeDomainsItem);

        JMenuItem copyInScopeDomainsWithSchemaItem = new JMenuItem("Copy In-Scope Domain Names with HTTP Schema");
        copyInScopeDomainsWithSchemaItem.addActionListener(e ->
                extractorService.extractAndCopyAsync(
                        ExtractionOptions_littlespidy.inScopeDomainsWithSchema(),
                        "Copy In-Scope Domain Names with HTTP Schema"
                )
        );
        menu.add(copyInScopeDomainsWithSchemaItem);

        return Collections.singletonList(menu);
    }
}
