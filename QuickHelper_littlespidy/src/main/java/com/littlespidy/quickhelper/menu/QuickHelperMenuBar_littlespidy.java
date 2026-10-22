// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.menu;

import com.littlespidy.quickhelper.model.ExtractionOptions_littlespidy;
import com.littlespidy.quickhelper.service.DomainExtractorService_littlespidy;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

/**
 * Builds the top-level Menu Bar for Quick Helper.
 */
public class QuickHelperMenuBar_littlespidy {

    private final DomainExtractorService_littlespidy extractorService;

    public QuickHelperMenuBar_littlespidy(DomainExtractorService_littlespidy extractorService) {
        this.extractorService = extractorService;
    }

    /**
     * Builds and returns the top-level JMenu for Burp Suite's main menu bar.
     *
     * @return populated JMenu
     */
    public JMenu createMenu() {
        JMenu menu = new JMenu("Quick Helper");

        JMenuItem copyAllDomainsItem = new JMenuItem("Copy All Domain Names");
        copyAllDomainsItem.setToolTipText("Copy all unique domain names from the site map to clipboard");
        copyAllDomainsItem.addActionListener(e ->
                extractorService.extractAndCopyAsync(
                        ExtractionOptions_littlespidy.allDomains(),
                        "Copy All Domain Names"
                )
        );
        menu.add(copyAllDomainsItem);

        JMenuItem copyAllDomainsWithSchemaItem = new JMenuItem("Copy All Domain Names with HTTP Schema");
        copyAllDomainsWithSchemaItem.setToolTipText("Copy all unique domain names with protocol schema (e.g. https://google.com) to clipboard");
        copyAllDomainsWithSchemaItem.addActionListener(e ->
                extractorService.extractAndCopyAsync(
                        ExtractionOptions_littlespidy.allDomainsWithSchema(),
                        "Copy All Domain Names with HTTP Schema"
                )
        );
        menu.add(copyAllDomainsWithSchemaItem);

        menu.addSeparator();

        JMenuItem copyInScopeDomainsItem = new JMenuItem("Copy In-Scope Domain Names");
        copyInScopeDomainsItem.setToolTipText("Copy unique in-scope domain names from the site map to clipboard");
        copyInScopeDomainsItem.addActionListener(e ->
                extractorService.extractAndCopyAsync(
                        ExtractionOptions_littlespidy.inScopeDomains(),
                        "Copy In-Scope Domain Names"
                )
        );
        menu.add(copyInScopeDomainsItem);

        JMenuItem copyInScopeDomainsWithSchemaItem = new JMenuItem("Copy In-Scope Domain Names with HTTP Schema");
        copyInScopeDomainsWithSchemaItem.setToolTipText("Copy unique in-scope domain names with HTTP schema to clipboard");
        copyInScopeDomainsWithSchemaItem.addActionListener(e ->
                extractorService.extractAndCopyAsync(
                        ExtractionOptions_littlespidy.inScopeDomainsWithSchema(),
                        "Copy In-Scope Domain Names with HTTP Schema"
                )
        );
        menu.add(copyInScopeDomainsWithSchemaItem);

        return menu;
    }
}
