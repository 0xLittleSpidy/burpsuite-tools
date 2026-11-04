// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.menu;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.littlespidy.quickhelper.model.ExtractionOptions_littlespidy;
import com.littlespidy.quickhelper.service.DomainExtractorService_littlespidy;
import com.littlespidy.quickhelper.service.ProxyAuthHistoryService_littlespidy;
import com.littlespidy.quickhelper.ui.QuickHelperRootTab_littlespidy;

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
    private final QuickHelperRootTab_littlespidy rootTab;
    private final ProxyAuthHistoryService_littlespidy proxyAuthHistoryService;

    public QuickHelperContextMenu_littlespidy(DomainExtractorService_littlespidy extractorService) {
        this(extractorService, null, null);
    }

    public QuickHelperContextMenu_littlespidy(DomainExtractorService_littlespidy extractorService,
                                             QuickHelperRootTab_littlespidy rootTab) {
        this(extractorService, rootTab, null);
    }

    public QuickHelperContextMenu_littlespidy(DomainExtractorService_littlespidy extractorService,
                                             QuickHelperRootTab_littlespidy rootTab,
                                             ProxyAuthHistoryService_littlespidy proxyAuthHistoryService) {
        this.extractorService = extractorService;
        this.rootTab = rootTab;
        this.proxyAuthHistoryService = proxyAuthHistoryService;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        JMenu menu = new JMenu("Quick Helper");

        // Repeater Request Editor Context Actions: Replace Recent JWT / Cookie without popup
        if (event.messageEditorRequestResponse().isPresent() && proxyAuthHistoryService != null) {
            var editorOpt = event.messageEditorRequestResponse();
            var editor = editorOpt.get();
            var reqResp = editor.requestResponse();
            if (reqResp != null && reqResp.request() != null) {
                HttpRequest currentReq = reqResp.request();

                JMenuItem replaceJwtItem = new JMenuItem("Replace Recent JWT");
                replaceJwtItem.addActionListener(e -> {
                    String recentJwt = proxyAuthHistoryService.findRecentJwtHeader(currentReq);
                    if (recentJwt != null && !recentJwt.trim().isEmpty()) {
                        HttpRequest updated = proxyAuthHistoryService.replaceJwt(currentReq, recentJwt);
                        editor.setRequest(updated);
                    }
                });
                menu.add(replaceJwtItem);

                JMenuItem replaceCookieItem = new JMenuItem("Replace Recent Session Cookie");
                replaceCookieItem.addActionListener(e -> {
                    String recentCookie = proxyAuthHistoryService.findRecentCookieHeader(currentReq);
                    if (recentCookie != null && !recentCookie.trim().isEmpty()) {
                        HttpRequest updated = proxyAuthHistoryService.replaceCookie(currentReq, recentCookie);
                        editor.setRequest(updated);
                    }
                });
                menu.add(replaceCookieItem);
                menu.addSeparator();
            }
        }

        if (rootTab != null) {
            JMenuItem downloadAllItem = new JMenuItem("Download All Extensions (Single Click)");
            downloadAllItem.addActionListener(e -> {
                rootTab.selectDownloaderTab();
                rootTab.getDownloaderTab().triggerDownloadAll();
            });
            menu.add(downloadAllItem);
            menu.addSeparator();
        }

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
