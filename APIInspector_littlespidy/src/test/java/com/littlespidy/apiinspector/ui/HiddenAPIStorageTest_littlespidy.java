// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.TestMockHelper_littlespidy;
import com.littlespidy.apiinspector.model.APIVersionPresets_littlespidy;
import com.littlespidy.apiinspector.model.HiddenEndpoint_littlespidy;
import com.littlespidy.apiinspector.persistence.APIInspectorPersistenceManager_littlespidy;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy.HiddenEndpointDTO;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import javax.swing.table.TableCellEditor;
import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

public class HiddenAPIStorageTest_littlespidy {

    @Test
    @DisplayName("Verify APIVersionPresets contains 1,091 version candidates with exact boundaries")
    public void testAPIVersionPresets() {
        List<String> extended = APIVersionPresets_littlespidy.getExtendedVersionsList();
        assertEquals(1091, extended.size(), "Extended versions list must contain exactly 1,091 elements");

        assertEquals("v0", extended.get(0));
        assertEquals("v1", extended.get(1));
        assertEquals("v1.01", extended.get(2));
        assertEquals("v9.99", extended.get(extended.size() - 1));

        // Check inclusion of specific user requested items
        assertTrue(extended.contains("v1.1"));
        assertTrue(extended.contains("v1.10"));
        assertTrue(extended.contains("v1.19"));
        assertTrue(extended.contains("v10"));
        assertTrue(extended.contains("v10.01"));
        assertTrue(extended.contains("v10.99"));
        assertTrue(extended.contains("v2"));
        assertTrue(extended.contains("v2.50"));
        assertTrue(extended.contains("v9"));
        assertTrue(extended.contains("v9.90"));

        // Comma separated string contains versions
        String comma = APIVersionPresets_littlespidy.getExtendedVersionsCommaSeparated();
        assertTrue(comma.startsWith("v0, v1, v1.01"));
        assertTrue(comma.endsWith("v9.99"));
    }

    @Test
    @DisplayName("Verify HiddenEndpointsTableModel supports double-click editable Source dropdown and Notes")
    public void testHiddenEndpointsTableModel() {
        HiddenEndpointsTableModel_littlespidy model = new HiddenEndpointsTableModel_littlespidy();
        AtomicBoolean stateChanged = new AtomicBoolean(false);
        model.setOnStateChanged(() -> stateChanged.set(true));

        assertEquals(8, model.getColumnCount());
        assertEquals("Source", model.getColumnName(1));
        assertEquals("Notes", model.getColumnName(7));

        HiddenEndpoint_littlespidy ep1 = new HiddenEndpoint_littlespidy(
                "Endpoint Discovery", "GET", "https://api.test.com/api/v1/hidden", "/api/v1/hidden", 200, "Initial note", null, null
        );
        model.addEndpoint(ep1);

        assertTrue(stateChanged.get());
        assertEquals(1, model.getRowCount());

        // Cell editability
        assertTrue(model.isCellEditable(0, 1), "Source column must be editable");
        assertTrue(model.isCellEditable(0, 7), "Notes column must be editable");
        assertFalse(model.isCellEditable(0, 0), "Index column must not be editable");
        assertFalse(model.isCellEditable(0, 3), "URL column must not be editable");

        // Inline double-click Source change
        stateChanged.set(false);
        model.setValueAt("JS Analysis", 0, 1);
        assertEquals("JS Analysis", ep1.getSource());
        assertTrue(stateChanged.get());

        // Inline Notes change
        stateChanged.set(false);
        model.setValueAt("Updated discovery notes", 0, 7);
        assertEquals("Updated discovery notes", ep1.getNotes());
        assertTrue(stateChanged.get());

        // Removal and clear
        HiddenEndpoint_littlespidy removed = model.removeEndpoint(0);
        assertEquals(ep1, removed);
        assertEquals(0, model.getRowCount());
    }

    @Test
    @DisplayName("Verify HiddenAPIStorageTab table cell editor is JComboBox dropdown and parallel viewers exist")
    public void testHiddenAPIStorageTabComponents() {
        HiddenAPIStorageTab_littlespidy tab = new HiddenAPIStorageTab_littlespidy(null);

        // Verify Source column (Column 1) has JComboBox cell editor
        TableCellEditor editor = tab.getEndpointsTable().getColumnModel().getColumn(1).getCellEditor();
        assertNotNull(editor, "Column 1 must have a custom TableCellEditor");
        assertTrue(editor instanceof DefaultCellEditor, "Editor must be DefaultCellEditor wrapping JComboBox");

        // Verify parallel Request/Response viewer split pane
        JSplitPane horizontalSplit = findHorizontalSplitPane(tab);
        assertNotNull(horizontalSplit, "HiddenAPIStorageTab must have a horizontal JSplitPane for parallel Request and Response viewers");
        assertEquals(JSplitPane.HORIZONTAL_SPLIT, horizontalSplit.getOrientation());

        // Verify 'Endpoint Details & Notes' tab is NOT present
        JTabbedPane subTabs = findComponent(tab, JTabbedPane.class);
        assertNull(subTabs, "Endpoint Details & Notes tabbed pane must be removed in favor of direct parallel viewers");
    }

    @Test
    @DisplayName("Verify endpoint ingestion from Burp tool HttpRequestResponse")
    public void testBurpToolIngestion() {
        HiddenAPIStorageTab_littlespidy tab = new HiddenAPIStorageTab_littlespidy(null);
        assertEquals(0, tab.getAllEndpoints().size());

        HttpRequest mockReq = TestMockHelper_littlespidy.createMockRequest("POST", "https://target.local/api/v2/secret", "/api/v2/secret", Map.of(), "{}");
        HttpResponse mockResp = TestMockHelper_littlespidy.createMockResponse(200, Map.of("Content-Type", "application/json"), "{\"status\": \"ok\"}");

        HttpRequestResponse rr = TestMockHelper_littlespidy.createMockHttpRequestResponse(mockReq, mockResp);

        tab.addEndpointFromBurpTool(rr, "Proxy History");

        assertEquals(1, tab.getAllEndpoints().size());
        HiddenEndpoint_littlespidy ingested = tab.getAllEndpoints().get(0);
        assertEquals("Proxy History", ingested.getSource());
        assertEquals("POST", ingested.getMethod());
        assertEquals("/api/v2/secret", ingested.getPath());
        assertEquals(200, ingested.getStatusCode());
        assertNotNull(ingested.getRawRequest());
        assertNotNull(ingested.getRawResponse());
    }

    @Test
    @DisplayName("Verify HiddenEndpoint serialization and deserialization in PersistenceManager")
    public void testPersistenceRoundTrip() {
        HiddenEndpoint_littlespidy ep = new HiddenEndpoint_littlespidy(
                "Repeater",
                "DELETE",
                "https://api.corp.local/api/v3/purge",
                "/api/v3/purge",
                403,
                "Admin auth failure test",
                null,
                null
        );
        ep.setParametersSummary("force=true");

        HiddenEndpointDTO dto = APIInspectorPersistenceManager_littlespidy.serializeHiddenEndpoint(ep);
        assertNotNull(dto);
        assertEquals("Repeater", dto.source);
        assertEquals("DELETE", dto.method);
        assertEquals("https://api.corp.local/api/v3/purge", dto.url);
        assertEquals("/api/v3/purge", dto.path);
        assertEquals(403, dto.statusCode);
        assertEquals("force=true", dto.parametersSummary);
        assertEquals("Admin auth failure test", dto.notes);

        HiddenEndpoint_littlespidy restored = APIInspectorPersistenceManager_littlespidy.deserializeHiddenEndpoint(dto);
        assertNotNull(restored);
        assertEquals(ep.getId(), restored.getId());
        assertEquals(ep.getSource(), restored.getSource());
        assertEquals(ep.getMethod(), restored.getMethod());
        assertEquals(ep.getUrl(), restored.getUrl());
        assertEquals(ep.getPath(), restored.getPath());
        assertEquals(ep.getStatusCode(), restored.getStatusCode());
        assertEquals(ep.getParametersSummary(), restored.getParametersSummary());
        assertEquals(ep.getNotes(), restored.getNotes());
    }

    @Test
    @DisplayName("Verify APIInspectorTab integrates Hidden API Storage as Suite Tab")
    public void testAPIInspectorTabIntegration() {
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(null);
        assertNotNull(rootTab.getHiddenApiStorageTab(), "Hidden API Storage tab must be instantiated and exposed");

        JTabbedPane pane = (JTabbedPane) rootTab.getComponent(1);
        assertEquals(11, pane.getTabCount(), "Suite tabbed pane must contain 11 tabs");
        assertEquals("Hidden API Storage", pane.getTitleAt(10));
    }

    private static JSplitPane findHorizontalSplitPane(Container container) {
        for (Component c : container.getComponents()) {
            if (c instanceof JSplitPane sp && sp.getOrientation() == JSplitPane.HORIZONTAL_SPLIT) {
                return sp;
            }
            if (c instanceof Container child) {
                JSplitPane found = findHorizontalSplitPane(child);
                if (found != null) return found;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static <T extends Component> T findComponent(Container container, Class<T> clazz) {
        for (Component c : container.getComponents()) {
            if (clazz.isInstance(c)) {
                return (T) c;
            }
            if (c instanceof Container child) {
                T found = findComponent(child, clazz);
                if (found != null) return found;
            }
        }
        return null;
    }
}
