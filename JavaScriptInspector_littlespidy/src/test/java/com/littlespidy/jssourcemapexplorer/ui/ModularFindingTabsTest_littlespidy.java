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
        assertEquals(1, panel.table.getValueAt(0, 1)); // Occurrences column
        assertEquals("POST", panel.table.getValueAt(0, 2));
        assertEquals("/api/v1/auth", panel.table.getValueAt(0, 3));
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

        DiscoveredSecret sec = new DiscoveredSecret("https://target.com/app.js", "JS File", "Cloud Secrets", "AKIAIOSFODNN7EXAMPLE", 3.8, "High", "AWS Access Key", 15, "let key = 'AKIA...'");
        JsFileEntry entry = new JsFileEntry(1, "https://target.com/app.js", "target.com", "/app.js", 200, 100, true, "1st Party", PassiveMapStatus.NOT_FOUND, null, null, null, null);
        entry.setJsReconFindings(List.of(sec), List.of());
        store.addEntry(entry);

        panel.refreshFromDataStore();
        assertEquals(1, panel.table.getRowCount());
        assertEquals(1, panel.table.getValueAt(0, 1)); // Occurrences column
        assertEquals("AWS Access Key", panel.table.getValueAt(0, 2)); // Token Type column
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
    @DisplayName("Verify JSSourceMapExplorerTab registers all 10 top-level tabs")
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
        assertNotNull(mainTab.getInternalIpAndSsnPanel());

        JTabbedPane rootTabs = findRootTabbedPane(mainTab);
        assertNotNull(rootTabs, "Root tabbed pane must exist");
        assertEquals(10, rootTabs.getTabCount(), "Must contain exactly 10 top-level tabs");

        assertEquals("JS and Source Map", rootTabs.getTitleAt(0));
        assertEquals("Paths", rootTabs.getTitleAt(1));
        assertEquals("Secrets", rootTabs.getTitleAt(2));
        assertEquals("Comments", rootTabs.getTitleAt(3));
        assertEquals("Security Bypasses", rootTabs.getTitleAt(4));
        assertEquals("Cloud URLs", rootTabs.getTitleAt(5));
        assertEquals("Dependencies", rootTabs.getTitleAt(6));
        assertEquals("Internal IPs & SSNs", rootTabs.getTitleAt(7));
        assertEquals("GraphQL", rootTabs.getTitleAt(8));
        assertEquals("AI Security Analyst", rootTabs.getTitleAt(9));
    }

    @Test
    @DisplayName("Verify Confidence, Entropy, Severity, Category, and Classification columns removed from findings tables")
    void testColumnsRemovedFromFindingTables() {
        MontoyaApi api = createMockApi();
        JsDataStore store = new JsDataStore();

        SecretsPanel_littlespidy secretsPanel = new SecretsPanel_littlespidy(api, store);
        JTable secTable = secretsPanel.getTable();
        assertEquals(8, secTable.getColumnCount(), "Secrets table should have 8 columns including Length");
        assertEquals("Length", secTable.getColumnName(4));
        for (int i = 0; i < secTable.getColumnCount(); i++) {
            String colName = secTable.getColumnName(i);
            assertNotEquals("Confidence", colName);
            assertNotEquals("Entropy", colName);
            assertNotEquals("Classification", colName);
            assertNotEquals("Severity", colName);
            assertNotEquals("Category", colName);
        }

        PathsPanel_littlespidy pathsPanel = new PathsPanel_littlespidy(api, store);
        JTable pathsTable = pathsPanel.getTable();
        assertEquals(8, pathsTable.getColumnCount(), "Paths table should have 8 columns");
        for (int i = 0; i < pathsTable.getColumnCount(); i++) {
            assertNotEquals("Classification", pathsTable.getColumnName(i));
        }

        CommentsPanel_littlespidy commentsPanel = new CommentsPanel_littlespidy(api, store);
        JTable commTable = commentsPanel.getTable();
        assertEquals(8, commTable.getColumnCount(), "Comments table should have 8 columns");
        for (int i = 0; i < commTable.getColumnCount(); i++) {
            assertNotEquals("Classification", commTable.getColumnName(i));
        }

        SecurityBypassesPanel_littlespidy bypassPanel = new SecurityBypassesPanel_littlespidy(api, store);
        JTable bypassTable = bypassPanel.getTable();
        assertEquals(9, bypassTable.getColumnCount(), "Security bypasses table should have 9 columns");
        for (int i = 0; i < bypassTable.getColumnCount(); i++) {
            assertNotEquals("Classification", bypassTable.getColumnName(i));
            assertNotEquals("Confidence", bypassTable.getColumnName(i));
        }

        CloudUrlsPanel_littlespidy cloudPanel = new CloudUrlsPanel_littlespidy(api, store);
        JTable cloudTable = cloudPanel.getTable();
        assertEquals(7, cloudTable.getColumnCount(), "Cloud URLs table should have 7 columns");
        for (int i = 0; i < cloudTable.getColumnCount(); i++) {
            assertNotEquals("Classification", cloudTable.getColumnName(i));
        }

        InternalIpAndSsnPanel_littlespidy ipSsnPanel = new InternalIpAndSsnPanel_littlespidy(api, store);
        JTable ipSsnTable = ipSsnPanel.getTable();
        assertEquals(8, ipSsnTable.getColumnCount(), "Internal IPs & SSNs table should have 8 columns");
        for (int i = 0; i < ipSsnTable.getColumnCount(); i++) {
            assertNotEquals("Classification", ipSsnTable.getColumnName(i));
        }

        DependenciesPanel_littlespidy depPanel = new DependenciesPanel_littlespidy(api, store);
        JTable depTable = depPanel.getTable();
        assertEquals(9, depTable.getColumnCount(), "Dependencies table should have 9 columns");
        for (int i = 0; i < depTable.getColumnCount(); i++) {
            assertNotEquals("Classification", depTable.getColumnName(i));
        }
    }

    @Test
    @DisplayName("Verify status displays No findings found when findings count is 0")
    void testNoFindingsFoundStatus() {
        MontoyaApi api = createMockApi();
        JsDataStore store = new JsDataStore();

        SecretsPanel_littlespidy secretsPanel = new SecretsPanel_littlespidy(api, store);
        secretsPanel.refreshFromDataStore();
        assertEquals("Secrets: 0 (No findings found)", secretsPanel.getStatsLabel().getText());

        PathsPanel_littlespidy pathsPanel = new PathsPanel_littlespidy(api, store);
        pathsPanel.refreshFromDataStore();
        assertEquals("Paths: 0 (No findings found)", pathsPanel.getStatsLabel().getText());

        CommentsPanel_littlespidy commentsPanel = new CommentsPanel_littlespidy(api, store);
        commentsPanel.refreshFromDataStore();
        assertEquals("Comments: 0 (No findings found)", commentsPanel.getStatsLabel().getText());
    }

    @Test
    @DisplayName("Verify batch multi-row selection classification applies to all selected rows")
    void testBatchMultiRowClassification() {
        MontoyaApi api = createMockApi();
        JsDataStore store = new JsDataStore();

        DiscoveredSecret sec1 = new DiscoveredSecret("https://target.com/app.js", "JS File", "AWS Key 1", "EXAMPLE_KEY_SAMPLE_1", 3.8, "High", "Regex", 10, "key1");
        DiscoveredSecret sec2 = new DiscoveredSecret("https://target.com/app.js", "JS File", "AWS Key 2", "EXAMPLE_KEY_SAMPLE_2", 3.8, "High", "Regex", 20, "key2");
        DiscoveredSecret sec3 = new DiscoveredSecret("https://target.com/app.js", "JS File", "AWS Key 3", "EXAMPLE_KEY_SAMPLE_3", 3.8, "High", "Regex", 30, "key3");

        JsFileEntry entry = new JsFileEntry(1, "https://target.com/app.js", "target.com", "/app.js", 200, 100, true, "1st Party", PassiveMapStatus.NOT_FOUND, null, null, null, null);
        entry.setJsReconFindings(List.of(sec1, sec2, sec3), List.of());
        store.addEntry(entry);

        SecretsPanel_littlespidy panel = new SecretsPanel_littlespidy(api, store);
        panel.refreshFromDataStore();

        JTable table = panel.getTable();
        assertEquals(3, table.getRowCount());

        // Select rows 0 and 2
        table.setRowSelectionInterval(0, 0);
        table.addRowSelectionInterval(2, 2);
        assertEquals(2, table.getSelectedRowCount());

        // Batch mark as True Positive
        panel.markSelectedClassification("True Positive");

        // Verify table selection is cleared after marking
        assertEquals(0, table.getSelectedRowCount());

        // Verify row 0 and row 2 are marked as True Positive, and row 1 remains Not Classified
        assertEquals("True Positive", panel.getClassificationAt(0));
        assertEquals("Not Classified", panel.getClassificationAt(1));
        assertEquals("True Positive", panel.getClassificationAt(2));
    }

    @Test
    @DisplayName("Verify duplicate findings grouping and occurrence navigation")
    void testDuplicateGroupingAndOccurrenceNavigation() {
        MontoyaApi api = createMockApi();
        JsDataStore store = new JsDataStore();

        DiscoveredComment c1 = new DiscoveredComment("https://target.com/app.js", "JS File", "Single-Line (//)", "TODO / FIXME", "TODO: remove debug flag", 10, 50, 75, "TODO: remove debug flag", "Not Classified");
        DiscoveredComment c2 = new DiscoveredComment("src/auth/login.ts", "SourceMap", "Single-Line (//)", "TODO / FIXME", "TODO: remove debug flag", 42, 120, 145, "TODO: remove debug flag", "Not Classified");
        DiscoveredComment c3 = new DiscoveredComment("src/admin/panel.ts", "SourceMap", "Single-Line (//)", "TODO / FIXME", "TODO: remove debug flag", 88, 300, 325, "TODO: remove debug flag", "Not Classified");

        JsFileEntry entry = new JsFileEntry(1, "https://target.com/app.js", "target.com", "/app.js", 200, 100, true, "1st Party", PassiveMapStatus.NOT_FOUND, null, null, null, null);
        entry.setJsReconFindings(List.of(), List.of(), List.of(), List.of(), List.of(c1), List.of());

        UnpackedProject project = new UnpackedProject("https://target.com/app.js.map");
        project.addFile(new UnpackedSourceFile("src/auth/login.ts", "login.ts", "console.log('hi');\n// TODO: remove debug flag", 2, 50, List.of(), List.of(), List.of(), List.of(), List.of(c2), List.of()));
        project.addFile(new UnpackedSourceFile("src/admin/panel.ts", "panel.ts", "let x = 1;\n// TODO: remove debug flag", 2, 50, List.of(), List.of(), List.of(), List.of(), List.of(c3), List.of()));
        entry.setUnpackedProject(project);
        store.addEntry(entry);

        CommentsPanel_littlespidy panel = new CommentsPanel_littlespidy(api, store);
        panel.refreshFromDataStore();

        // Must be grouped into exactly 1 row
        assertEquals(1, panel.getTable().getRowCount());
        // Occurrences column must be 3
        assertEquals(3, panel.getTable().getValueAt(0, 1));
        assertEquals("TODO: remove debug flag", panel.getTable().getValueAt(0, 4));

        // Occurrences list must have all 3
        List<FindingOccurrence_littlespidy> occurrences = panel.getOccurrencesAt(0);
        assertEquals(3, occurrences.size());
        assertEquals("https://target.com/app.js", occurrences.get(0).sourceLocation());
        assertEquals("src/auth/login.ts", occurrences.get(1).sourceLocation());
        assertEquals("src/admin/panel.ts", occurrences.get(2).sourceLocation());

        // Select row 0 and batch mark as True Positive
        panel.getTable().setRowSelectionInterval(0, 0);
        panel.markSelectedClassification("True Positive");
        assertEquals("True Positive", panel.getClassificationAt(0));
        assertEquals("True Positive", entry.getJsComments().get(0).classification());
        assertEquals("True Positive", entry.getUnpackedProject().getAllComments().get(0).classification());
        assertEquals("True Positive", entry.getUnpackedProject().getAllComments().get(1).classification());
    }

    @Test
    @DisplayName("Verify unpacked finding location resolves to parent entry and loads source code in viewer")
    void testUnpackedFindingRequestResponseResolution() {
        MontoyaApi api = createMockApi();
        JsDataStore store = new JsDataStore();

        JsFileEntry entry = new JsFileEntry(1, "https://target.com/static/js/main.js", "target.com", "/static/js/main.js", 200, 500, true, "1st Party", PassiveMapStatus.NOT_FOUND, null, null, null, null);
        UnpackedProject project = new UnpackedProject("https://target.com/static/js/main.js.map");

        String sourceCode = "import React from 'react';\n// TODO: replace mock token with real auth\nconst token = 'xyz';";
        DiscoveredComment comm = new DiscoveredComment("src/auth/AuthProvider.tsx", "SourceMap", "Single-Line (//)", "TODO / FIXME", "TODO: replace mock token with real auth", 2, 28, 69, "// TODO: replace mock token with real auth", "Not Classified");

        project.addFile(new UnpackedSourceFile("src/auth/AuthProvider.tsx", "AuthProvider.tsx", sourceCode, 3, sourceCode.length(), List.of(), List.of(), List.of(), List.of(), List.of(comm), List.of()));
        entry.setUnpackedProject(project);
        store.addEntry(entry);

        CommentsPanel_littlespidy panel = new CommentsPanel_littlespidy(api, store);
        panel.refreshFromDataStore();

        assertEquals(1, panel.getTable().getRowCount());
        panel.getTable().setRowSelectionInterval(0, 0);

        List<FindingOccurrence_littlespidy> occList = panel.getOccurrencesAt(0);
        assertEquals(1, occList.size());
        assertEquals("src/auth/AuthProvider.tsx", occList.get(0).sourceLocation());
        assertEquals("TODO: replace mock token with real auth", occList.get(0).findingText());
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
