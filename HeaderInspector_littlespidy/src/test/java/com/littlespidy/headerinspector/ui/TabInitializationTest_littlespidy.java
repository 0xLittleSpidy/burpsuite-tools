// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.littlespidy.headerinspector.cache.model.CacheDataStore;
import com.littlespidy.headerinspector.cache.ui.CacheInspectorTab;
import com.littlespidy.headerinspector.collector.model.HeaderCollectorDataStore;
import com.littlespidy.headerinspector.collector.ui.HeaderCollectorTab;
import com.littlespidy.headerinspector.csp.model.CSPDataStore;
import com.littlespidy.headerinspector.csp.ui.CSPInspectorTab;
import com.littlespidy.headerinspector.hsts.model.HSTSDataStore;
import com.littlespidy.headerinspector.hsts.ui.HSTSInspectorTab;
import com.littlespidy.headerinspector.method.model.MethodCollectorDataStore;
import com.littlespidy.headerinspector.method.ui.MethodCollectorTab;
import com.littlespidy.headerinspector.status.model.StatusCollectorDataStore;
import com.littlespidy.headerinspector.status.ui.StatusCollectorTab;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JPanel;
import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Verifies that MethodCollectorTab and StatusCollectorTab initialize cleanly
 * without ArrayIndexOutOfBoundsException or table column configuration errors.
 *
 * @author littlespidy
 */
class TabInitializationTest_littlespidy {

    @SuppressWarnings("unchecked")
    private static <T> T createDummy(Class<T> iface) {
        return (T) Proxy.newProxyInstance(
                iface.getClassLoader(),
                new Class<?>[]{iface},
                (proxy, method, args) -> {
                    if (method.getReturnType().equals(JComponent.class) || method.getReturnType().equals(java.awt.Component.class)) {
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

    @Test
    void testMethodCollectorTabInitialization() {
        MontoyaApi api = createMockMontoyaApi();
        MethodCollectorDataStore dataStore = new MethodCollectorDataStore();

        assertDoesNotThrow(() -> {
            MethodCollectorTab tab = new MethodCollectorTab(api, dataStore);
            assertNotNull(tab);
        }, "MethodCollectorTab should initialize without throwing ArrayIndexOutOfBoundsException");
    }

    @Test
    void testStatusCollectorTabInitialization() {
        MontoyaApi api = createMockMontoyaApi();
        StatusCollectorDataStore dataStore = new StatusCollectorDataStore();

        assertDoesNotThrow(() -> {
            StatusCollectorTab tab = new StatusCollectorTab(api, dataStore);
            assertNotNull(tab);
        }, "StatusCollectorTab should initialize without throwing ArrayIndexOutOfBoundsException");
    }

    @Test
    void testHeaderCollectorTabInitialization() {
        MontoyaApi api = createMockMontoyaApi();
        HeaderCollectorDataStore dataStore = new HeaderCollectorDataStore();

        assertDoesNotThrow(() -> {
            HeaderCollectorTab tab = new HeaderCollectorTab(api, dataStore);
            assertNotNull(tab);
        }, "HeaderCollectorTab should initialize without throwing exceptions");
    }

    @Test
    void testCSPInspectorTabInitialization() {
        MontoyaApi api = createMockMontoyaApi();
        CSPDataStore dataStore = new CSPDataStore();

        assertDoesNotThrow(() -> {
            CSPInspectorTab tab = new CSPInspectorTab(api, dataStore);
            assertNotNull(tab);
        }, "CSPInspectorTab should initialize without throwing exceptions");
    }

    @Test
    void testHSTSInspectorTabInitialization() {
        MontoyaApi api = createMockMontoyaApi();
        HSTSDataStore dataStore = new HSTSDataStore();

        assertDoesNotThrow(() -> {
            HSTSInspectorTab tab = new HSTSInspectorTab(api, dataStore);
            assertNotNull(tab);
        }, "HSTSInspectorTab should initialize without throwing exceptions");
    }

    @Test
    void testCacheInspectorTabInitialization() {
        MontoyaApi api = createMockMontoyaApi();
        CacheDataStore dataStore = new CacheDataStore();

        assertDoesNotThrow(() -> {
            CacheInspectorTab tab = new CacheInspectorTab(api, dataStore);
            assertNotNull(tab);
        }, "CacheInspectorTab should initialize without throwing exceptions");
    }
}
