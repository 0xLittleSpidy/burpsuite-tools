// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import com.littlespidy.payloadinjector.model.InjectionSettings;
import com.littlespidy.payloadinjector.model.ParamPayloadStore;
import com.littlespidy.payloadinjector.model.SmugglingPayloadStore;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Master Suite Tab containing dedicated tabs for all JSON payload categories.
 * Tabs wrap across multiple rows down below without scroll bars.
 *
 * @author littlespidy
 */
public class PayloadInjectorTab extends JPanel {

    private com.littlespidy.payloadinjector.storage.PayloadInjectorPersistentStorageManager_littlespidy storageManager;

    public void setStorageManager(com.littlespidy.payloadinjector.storage.PayloadInjectorPersistentStorageManager_littlespidy storageManager) {
        this.storageManager = storageManager;
        add(storageManager.createSessionToolbar(), BorderLayout.NORTH);
        revalidate();
        repaint();
    }

    public PayloadInjectorTab(Map<String, ParamPayloadStore> paramStores,
                              SmugglingPayloadStore smugglingStore,
                              com.littlespidy.payloadinjector.model.FilePathStore_littlespidy linuxFilePathStore,
                              com.littlespidy.payloadinjector.model.FilePathStore_littlespidy windowsFilePathStore,
                              InjectionSettings settings) {
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(tabbedPane.getFont().deriveFont(Font.BOLD, 12f));

        // WRAP_TAB_LAYOUT ensures tabs wrap to multiple rows down below without any scroll bar
        tabbedPane.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);

        // File Paths tab as the first tab in the extension's UI
        if (linuxFilePathStore != null || windowsFilePathStore != null) {
            tabbedPane.addTab("File Paths", new FilePathsTab_littlespidy(linuxFilePathStore, windowsFilePathStore));
        }

        // Core categories
        if (paramStores != null && paramStores.containsKey("XSS")) {
            tabbedPane.addTab("XSS", new ParamPayloadTab("XSS", paramStores.get("XSS"), settings));
        }
        if (paramStores != null && paramStores.containsKey("CSTI")) {
            tabbedPane.addTab("CSTI", new ParamPayloadTab("CSTI", paramStores.get("CSTI"), settings));
        }
        if (paramStores != null && paramStores.containsKey("SQL")) {
            tabbedPane.addTab("SQL", new ParamPayloadTab("SQL", paramStores.get("SQL"), settings));
        }

        // HTTP Request Smuggling tab
        if (smugglingStore != null) {
            tabbedPane.addTab("HTTP Request Smuggling", new SmugglingPayloadTab(smugglingStore));
        }

        // Append all remaining JSON payload category tabs down below
        if (paramStores != null) {
            for (Map.Entry<String, ParamPayloadStore> entry : paramStores.entrySet()) {
                String name = entry.getKey();
                if ("XSS".equals(name) || "CSTI".equals(name) || "SQL".equals(name)) {
                    continue;
                }
                tabbedPane.addTab(name, new ParamPayloadTab(name, entry.getValue(), settings));
            }
        }

        add(tabbedPane, BorderLayout.CENTER);
    }

    public PayloadInjectorTab(Map<String, ParamPayloadStore> paramStores,
                              SmugglingPayloadStore smugglingStore,
                              InjectionSettings settings) {
        this(paramStores, smugglingStore, null, null, settings);
    }

    public PayloadInjectorTab(ParamPayloadStore xssStore,
                              ParamPayloadStore cstiStore,
                              ParamPayloadStore sqlStore,
                              SmugglingPayloadStore smugglingStore,
                              InjectionSettings settings) {
        this(buildLegacyMap(xssStore, cstiStore, sqlStore), smugglingStore, settings);
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
}

