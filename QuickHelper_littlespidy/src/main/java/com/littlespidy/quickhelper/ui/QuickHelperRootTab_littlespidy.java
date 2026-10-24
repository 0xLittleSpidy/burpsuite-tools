// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.quickhelper.service.ClipboardService_littlespidy;
import com.littlespidy.quickhelper.service.DomainExtractorService_littlespidy;
import com.littlespidy.quickhelper.service.ExtensionCatalogService_littlespidy;
import com.littlespidy.quickhelper.service.ExtensionDownloaderService_littlespidy;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;

/**
 * Root Suite Tab registered with Burp Suite under 'Quick Helper'.
 */
public class QuickHelperRootTab_littlespidy extends JPanel {

    private final JTabbedPane tabbedPane;
    private final ExtensionDownloaderTab_littlespidy downloaderTab;
    private final DomainExtractorTab_littlespidy extractorTab;

    public QuickHelperRootTab_littlespidy(MontoyaApi api,
                                         ExtensionCatalogService_littlespidy catalogService,
                                         ExtensionDownloaderService_littlespidy downloaderService,
                                         DomainExtractorService_littlespidy domainExtractorService,
                                         ClipboardService_littlespidy clipboardService) {
        setLayout(new BorderLayout());

        this.downloaderTab = new ExtensionDownloaderTab_littlespidy(api, catalogService, downloaderService);
        this.extractorTab = new DomainExtractorTab_littlespidy(domainExtractorService, clipboardService);

        this.tabbedPane = new JTabbedPane();
        this.tabbedPane.addTab("Extensions Downloader", downloaderTab);
        this.tabbedPane.addTab("Domain Extractor", extractorTab);

        add(tabbedPane, BorderLayout.CENTER);
    }

    public ExtensionDownloaderTab_littlespidy getDownloaderTab() {
        return downloaderTab;
    }

    public DomainExtractorTab_littlespidy getExtractorTab() {
        return extractorTab;
    }

    public void selectDownloaderTab() {
        tabbedPane.setSelectedComponent(downloaderTab);
    }

    public void selectExtractorTab() {
        tabbedPane.setSelectedComponent(extractorTab);
    }
}
