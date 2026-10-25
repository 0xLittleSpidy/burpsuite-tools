// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.headerinspector.HeaderInspectorRootTab;
import com.littlespidy.headerinspector.cache.model.CacheDataStore;
import com.littlespidy.headerinspector.csp.model.CSPDataStore;
import com.littlespidy.headerinspector.hsts.model.HSTSDataStore;
import com.littlespidy.headerinspector.ui.common.MultiSelectFilterButton;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.Component;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Unit tests verifying MultiSelectFilterButton default selection behavior,
 * OPTIONS exclusion logic across data stores, and RootTab welcome tab removal.
 *
 * @author littlespidy
 */
class MultiSelectFilterButtonTest_littlespidy {

    private static final List<String> METHOD_OPTIONS = List.of(
            "All Methods", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
    );
    private static final Set<String> DEFAULT_METHODS = Set.of(
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"
    );

    @Test
    void testDefaultMethodSelectionExcludesOptions() {
        MultiSelectFilterButton button = new MultiSelectFilterButton(
                "Method",
                METHOD_OPTIONS,
                DEFAULT_METHODS,
                sel -> {}
        );

        Set<String> selected = button.getSelected();
        assertEquals(6, selected.size());
        assertTrue(selected.contains("GET"));
        assertTrue(selected.contains("POST"));
        assertTrue(selected.contains("PUT"));
        assertTrue(selected.contains("PATCH"));
        assertTrue(selected.contains("DELETE"));
        assertTrue(selected.contains("HEAD"));
        assertFalse(selected.contains("OPTIONS"));
        assertEquals("Method: 6 selected [v]", button.getText());
    }

    @Test
    void testDataStoresMatchLogicWithDefaultSelection() {
        MultiSelectFilterButton button = new MultiSelectFilterButton(
                "Method",
                METHOD_OPTIONS,
                DEFAULT_METHODS,
                sel -> {}
        );

        Set<String> selected = button.getSelected();

        // CacheDataStore
        assertTrue(CacheDataStore.matchesMethod("GET", selected));
        assertTrue(CacheDataStore.matchesMethod("POST", selected));
        assertFalse(CacheDataStore.matchesMethod("OPTIONS", selected));

        // CSPDataStore
        assertTrue(CSPDataStore.matchesMethod("GET", selected));
        assertTrue(CSPDataStore.matchesMethod("POST", selected));
        assertFalse(CSPDataStore.matchesMethod("OPTIONS", selected));

        // HSTSDataStore
        assertTrue(HSTSDataStore.matchesMethod("GET", selected));
        assertTrue(HSTSDataStore.matchesMethod("POST", selected));
        assertFalse(HSTSDataStore.matchesMethod("OPTIONS", selected));
    }

    @Test
    void testResetToDefaultRestoresSelection() {
        MultiSelectFilterButton button = new MultiSelectFilterButton(
                "Method",
                METHOD_OPTIONS,
                DEFAULT_METHODS,
                sel -> {}
        );

        button.clearSelection();
        assertTrue(button.getSelected().isEmpty());
        assertEquals("Method [v]", button.getText());

        button.resetToDefault();
        Set<String> restored = button.getSelected();
        assertEquals(6, restored.size());
        assertFalse(restored.contains("OPTIONS"));
        assertTrue(restored.contains("GET"));
        assertEquals("Method: 6 selected [v]", button.getText());
    }

    @Test
    void testSelectingAllIncludesOptions() {
        MultiSelectFilterButton button = new MultiSelectFilterButton(
                "Method",
                METHOD_OPTIONS,
                DEFAULT_METHODS,
                sel -> {}
        );

        button.setSelected(Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"));
        Set<String> allSelected = button.getSelected();
        assertEquals(7, allSelected.size());
        assertTrue(allSelected.contains("OPTIONS"));
        assertTrue(CacheDataStore.matchesMethod("OPTIONS", allSelected));
        assertTrue(CSPDataStore.matchesMethod("OPTIONS", allSelected));
        assertTrue(HSTSDataStore.matchesMethod("OPTIONS", allSelected));
    }

    @Test
    void testRootTabExcludesWelcomeTab() {
        MontoyaApi api = createMockMontoyaApi();
        HeaderInspectorRootTab rootTab = new HeaderInspectorRootTab(api);

        JTabbedPane tabbedPane = null;
        for (Component comp : rootTab.getComponents()) {
            if (comp instanceof JTabbedPane tp) {
                tabbedPane = tp;
                break;
            }
        }

        assertNotNull(tabbedPane, "RootTab should contain a JTabbedPane");
        assertEquals(6, tabbedPane.getTabCount(), "RootTab should have exactly 6 workspace tabs");
        assertEquals("Header Collector", tabbedPane.getTitleAt(0));
        assertEquals("Method Collector", tabbedPane.getTitleAt(1));
        assertEquals("Status Collector", tabbedPane.getTitleAt(2));
        assertEquals("Cache Inspector", tabbedPane.getTitleAt(3));
        assertEquals("CSP Inspector", tabbedPane.getTitleAt(4));
        assertEquals("HSTS Inspector", tabbedPane.getTitleAt(5));

        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            assertNotEquals("Welcome & Guide", tabbedPane.getTitleAt(i));
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T createDummy(Class<T> iface) {
        return (T) Proxy.newProxyInstance(
                iface.getClassLoader(),
                new Class<?>[]{iface},
                (proxy, method, args) -> {
                    if (method.getReturnType().equals(JComponent.class) || method.getReturnType().equals(Component.class)) {
                        return new JPanel();
                    }
                    if (method.getReturnType().equals(String.class)) {
                        return "";
                    }
                    if (method.getReturnType().equals(boolean.class)) {
                        return false;
                    }
                    if (method.getReturnType().equals(int.class)) {
                        return 0;
                    }
                    return null;
                }
        );
    }

    private static MontoyaApi createMockMontoyaApi() {
        HttpRequestEditor reqEditor = createDummy(HttpRequestEditor.class);
        HttpResponseEditor respEditor = createDummy(HttpResponseEditor.class);

        UserInterface ui = (UserInterface) Proxy.newProxyInstance(
                UserInterface.class.getClassLoader(),
                new Class<?>[]{UserInterface.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "createHttpRequestEditor" -> reqEditor;
                    case "createHttpResponseEditor" -> respEditor;
                    default -> null;
                }
        );

        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(),
                new Class<?>[]{MontoyaApi.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "userInterface" -> ui;
                    default -> null;
                }
        );
    }
}
