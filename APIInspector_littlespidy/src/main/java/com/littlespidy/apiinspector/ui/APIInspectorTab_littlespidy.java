// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;

/**
 * Root Suite Tab container for the API Inspector extension.
 */
public class APIInspectorTab_littlespidy extends JPanel {

    private final ResAPIVersionFinderTab_littlespidy versionFinderTab;

    public APIInspectorTab_littlespidy(MontoyaApi api) {
        super(new BorderLayout());
        JTabbedPane rootTabbedPane = new JTabbedPane();

        this.versionFinderTab = new ResAPIVersionFinderTab_littlespidy(api);
        rootTabbedPane.addTab("ResAPI Version Finder", versionFinderTab);

        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public ResAPIVersionFinderTab_littlespidy getVersionFinderTab() {
        return versionFinderTab;
    }
}
