// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.jssourcemapexplorer.model.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying that the 6 individual finding tabs (Paths, Secrets, Comments,
 * Security Bypasses, Cloud URLs, Dependencies) initialize properly with parallel
 * Request and Response editors (50/50 split), and that JSSourceMapExplorerTab hosts
 * all 9 modular top-level suite tabs.
 *
 * @author littlespidy
 */
class ModularFindingTabsTest_littlespidy {

    @SuppressWarnings("unchecked")
    private <T> T createMock(Class<T> iface) {
        return (T) Proxy.newProxyInstance(
            iface.getClassLoader(),
            new Class<?>[]{iface},
            (proxy, method, args) -> {
                Class<?> ret = method.getReturnType();
                if (ret == boolean.class) return false;
                if (ret == int.class) return 0;
                if (ret == long.class) return 0L;
                if (ret == double.class) return 0.0;
                if (ret == String.class) return "";
                if (Component.class.isAssignableFrom(ret)) return new JPanel();
                if (ret.isInterface()) return createMock(ret);
                return null;
            }
        );
    }

    private MontoyaApi createMockApi() {
        HttpRequestEditor reqEditor = createMock(HttpRequestEditor.class);
        HttpResponseEditor respEditor = createMock(HttpResponseEditor.class);

        return (MontoyaApi) Proxy.newProxyInstance(
            MontoyaApi.class.getClassLoader(),
            new Class<?>[]{MontoyaApi.class},
            (proxy, method, args) -> {
                if ("userInterface".equals(method.getName())) {
                    return (UserInterface) Proxy.newProxyInstance(
                        UserInterface.class.getClassLoader(),
                        new Class<?>[]{UserInterface.class},
                        (pUi, mUi, aUi) -> {
                            if ("createHttpRequestEditor".equals(mUi.getName())) return reqEditor;
                            if ("createHttpResponseEditor".equals(mUi.getName())) return respEditor;
                            Class<?> r = mUi.getReturnType();
                            if (Component.class.isAssignableFrom(r)) return new JPanel();
                            if (r.isInterface()) return createMock(r);
                            return null;
                        }
                    );
                }
                Class<?> ret = method.getReturnType();
                if (ret.isInterface()) return createMock(ret);
                return null;
            }
        );
    }

    @Test
    @DisplayName("Verify PathsPanel_littlespidy initializes with parallel 50/50 editors and model")
    void testPathsPanelInitialization() {
        MontoyaApi api = createMockApi();
        JsDataStore store = new JsDataStore();

        PathsPanel_littlespidy panel = new PathsPanel_littlespidy(api, store);
        assertNotNull(panel);

        JSplitPane horizontalSplit = findHorizontalSplitPane(panel);
        assertNotNull(horizontalSplit, "Must contain a horizontal JSplitPane for parallel editors");
        assertEquals(0.5, horizontalSplit.getResizeWeight(), 0.01, "Parallel editors must have 0.5 resize weight");

        // Verify finding population
        DiscoveredEndpoint ep = new DiscoveredEndpoint("https://target.com/app.js", "JS File", "/api/v1/auth", "POST", 12, "fetch('/api/v1/auth')", "Regex");
        JsFileEntry entry = new JsFileEntry(1, "https://target.com/app.js", "target.com", "/app.js", 200, 100, true, "1st Party", PassiveMapStatus.NOT_FOUND, null, null, null, null);
        entry.setJsReconFindings(List.of(), List.of(ep));
        store.addEntry(entry);

        panel.refreshFromDataStore();
        assertEquals(1, panel.table.getRowCount());
        assertEquals("POST", panel.table.getValueAt(0, 1));
        assertEquals("/api/v1/auth", panel.table.getValueAt(0, 2));
    }

    @Test
    @DisplayName("Verify SecretsPanel_littlespidy initializes with parallel editors and model")
    void testSecretsPanelInitialization() {
        MontoyaApi api = createMockApi();
        JsDataStore store = new JsDataStore();

        SecretsPanel_littlespidy panel = new SecretsPanel_littlespidy(api, store);
        assertNotNull(panel);

        JSplitPane horizontalSplit = findHorizontalSplitPane(panel);
        assertNotNull(horizontalSplit, "Must contain horizontal JSplitPane for parallel editors");
        assertEquals(0.5, horizontalSplit.getResizeWeight(), 0.01);

        DiscoveredSecret sec = new DiscoveredSecret("https://target.com/app.js", "JS File", "AWS Access Key", "AKIAIOSFODNN7EXAMPLE", 3.8, "High", "Regex", 15, "let key = 'AKIA...'");
        JsFileEntry entry = new JsFileEntry(1, "https://target.com/app.js", "target.com", "/app.js", 200, 100, true, "1st Party", PassiveMapStatus.NOT_FOUND, null, null, null, null);
        entry.setJsReconFindings(List.of(sec), List.of());
        store.addEntry(entry);

        panel.refreshFromDataStore();
        assertEquals(1, panel.table.getRowCount());
        assertEquals("AWS Access Key", panel.table.getValueAt(0, 1));
    }

    @Test
    @DisplayName("Verify Comments, Bypasses, Cloud, and Dependencies panels initialize properly")
    void testRemainingPanelsInitialization() {
        MontoyaApi api = createMockApi();
        JsDataStore store = new JsDataStore();

        CommentsPanel_littlespidy commentsPanel = new CommentsPanel_littlespidy(api, store);
        assertNotNull(commentsPanel);
        assertNotNull(findHorizontalSplitPane(commentsPanel));

        SecurityBypassesPanel_littlespidy bypassPanel = new SecurityBypassesPanel_littlespidy(api, store);
        assertNotNull(bypassPanel);
        assertNotNull(findHorizontalSplitPane(bypassPanel));

        CloudUrlsPanel_littlespidy cloudPanel = new CloudUrlsPanel_littlespidy(api, store);
        assertNotNull(cloudPanel);
        assertNotNull(findHorizontalSplitPane(cloudPanel));

        DependenciesPanel_littlespidy depPanel = new DependenciesPanel_littlespidy(api, store);
        assertNotNull(depPanel);
        assertNotNull(findHorizontalSplitPane(depPanel));
    }

    @Test
    @DisplayName("Verify JSSourceMapExplorerTab registers all 9 top-level tabs")
    void testTopLevelTabsRegistered() {
        MontoyaApi api = createMockApi();
        JsDataStore store = new JsDataStore();

        JSSourceMapExplorerTab mainTab = new JSSourceMapExplorerTab(api, store);
        assertNotNull(mainTab.getPathsPanel());
        assertNotNull(mainTab.getSecretsPanel());
        assertNotNull(mainTab.getCommentsPanel());
        assertNotNull(mainTab.getSecurityBypassesPanel());
        assertNotNull(mainTab.getCloudUrlsPanel());
        assertNotNull(mainTab.getDependenciesPanel());

        JTabbedPane rootTabs = findRootTabbedPane(mainTab);
        assertNotNull(rootTabs, "Root tabbed pane must exist");
        assertEquals(9, rootTabs.getTabCount(), "Must contain exactly 9 top-level tabs");

        assertEquals("JS and Source Map", rootTabs.getTitleAt(0));
        assertEquals("Paths", rootTabs.getTitleAt(1));
        assertEquals("Secrets", rootTabs.getTitleAt(2));
        assertEquals("Comments", rootTabs.getTitleAt(3));
        assertEquals("Security Bypasses", rootTabs.getTitleAt(4));
        assertEquals("Cloud URLs", rootTabs.getTitleAt(5));
        assertEquals("Dependencies", rootTabs.getTitleAt(6));
        assertEquals("GraphQL", rootTabs.getTitleAt(7));
        assertEquals("AI Security Analyst", rootTabs.getTitleAt(8));
    }

    private JSplitPane findHorizontalSplitPane(Container root) {
        for (Component c : root.getComponents()) {
            if (c instanceof JSplitPane sp) {
                if (sp.getOrientation() == JSplitPane.HORIZONTAL_SPLIT) {
                    return sp;
                }
                JSplitPane nested = findHorizontalSplitPane(sp);
                if (nested != null) return nested;
            } else if (c instanceof Container child) {
                JSplitPane nested = findHorizontalSplitPane(child);
                if (nested != null) return nested;
            }
        }
        return null;
    }

    private JTabbedPane findRootTabbedPane(Container root) {
        for (Component c : root.getComponents()) {
            if (c instanceof JTabbedPane tp) {
                return tp;
            } else if (c instanceof Container child) {
                JTabbedPane nested = findRootTabbedPane(child);
                if (nested != null) return nested;
            }
        }
        return null;
    }
}
