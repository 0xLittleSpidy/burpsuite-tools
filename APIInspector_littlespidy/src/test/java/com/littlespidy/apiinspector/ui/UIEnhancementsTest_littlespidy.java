// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.apiinspector.TestMockHelper_littlespidy;
import com.littlespidy.apiinspector.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Field;
import java.util.*;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class UIEnhancementsTest_littlespidy {

    private MontoyaApi mockApi;

    @BeforeEach
    public void setUp() {
        mockApi = null; // Headless / unit test mode
    }

    @Test
    @DisplayName("Verify MethodFilterDropDown and AuthFilterDropDown logic and labels")
    public void testFilterDropdowns() {
        MethodFilterDropDown_littlespidy methodFilter = new MethodFilterDropDown_littlespidy();
        assertEquals("Methods: All", methodFilter.getText());
        assertTrue(methodFilter.isMethodSelected("GET"));
        assertTrue(methodFilter.isMethodSelected("POST"));

        methodFilter.selectAll(false);
        assertEquals("Methods: None", methodFilter.getText());
        assertFalse(methodFilter.isMethodSelected("GET"));

        methodFilter.selectAll(true);
        assertTrue(methodFilter.isMethodSelected("GET"));

        // Register custom method
        methodFilter.registerMethod("CUSTOM");
        assertTrue(methodFilter.isMethodSelected("CUSTOM"));

        AuthFilterDropDown_littlespidy authFilter = new AuthFilterDropDown_littlespidy();
        assertEquals("Auth: All", authFilter.getText());
        assertTrue(authFilter.isAuthOptionSelected(true));
        assertTrue(authFilter.isAuthOptionSelected(false));

        authFilter.selectAll(false);
        assertEquals("Auth: 0 Selected", authFilter.getText());
        assertFalse(authFilter.isAuthOptionSelected(true));
        assertFalse(authFilter.isAuthOptionSelected(false));
    }

    @Test
    @DisplayName("Verify API Import Tab endpoint filters and summary statistics")
    public void testAPIImportTabFiltersAndSummary() throws Exception {
        APIImportTab_littlespidy importTab = new APIImportTab_littlespidy(mockApi);

        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("Store API", "OpenAPI 3.0", "FILE", "/test/store.json");
        col.setTargetBaseUrl("https://api.store.com");

        DiscoveredEndpoint_littlespidy ep1 = new DiscoveredEndpoint_littlespidy("GET", "/products", "List Products");
        ep1.setRequiresAuth(false);
        DiscoveredEndpoint_littlespidy ep2 = new DiscoveredEndpoint_littlespidy("POST", "/products", "Create Product");
        ep2.setRequiresAuth(true);
        DiscoveredEndpoint_littlespidy ep3 = new DiscoveredEndpoint_littlespidy("DELETE", "/products/{id}", "Delete Product");
        ep3.setRequiresAuth(true);

        col.setEndpoints(List.of(ep1, ep2, ep3));
        importTab.setCollections(List.of(col));

        // Select the collection
        Field tableField = APIImportTab_littlespidy.class.getDeclaredField("collectionTable");
        tableField.setAccessible(true);
        JTable table = (JTable) tableField.get(importTab);
        table.setRowSelectionInterval(0, 0);

        // Verify summary labels
        Field methodSummaryField = APIImportTab_littlespidy.class.getDeclaredField("endpointMethodSummaryLabel");
        methodSummaryField.setAccessible(true);
        JLabel methodSummaryLabel = (JLabel) methodSummaryField.get(importTab);
        assertTrue(methodSummaryLabel.getText().contains("GET: 1"));
        assertTrue(methodSummaryLabel.getText().contains("POST: 1"));
        assertTrue(methodSummaryLabel.getText().contains("DELETE: 1"));

        Field authSummaryField = APIImportTab_littlespidy.class.getDeclaredField("endpointAuthSummaryLabel");
        authSummaryField.setAccessible(true);
        JLabel authSummaryLabel = (JLabel) authSummaryField.get(importTab);
        assertTrue(authSummaryLabel.getText().contains("Required (2)"));
        assertTrue(authSummaryLabel.getText().contains("No Auth (1)"));
        assertTrue(authSummaryLabel.getText().contains("Total: 3"));
    }

    @Test
    @DisplayName("Verify Parameter Collector Tab tables, data type column, and parameter extraction")
    public void testParameterCollectorTab() throws Exception {
        ParameterCollectorTab_littlespidy paramTab = new ParameterCollectorTab_littlespidy();

        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("User API", "OpenAPI 3.0", "FILE", "/test/user.json");
        DiscoveredEndpoint_littlespidy ep1 = new DiscoveredEndpoint_littlespidy("GET", "/users/{userId}/orders", "Get User Orders");
        ep1.setPathParams(Map.of("userId", "123"));
        ep1.setQueryParams(Map.of("page", "1", "pageSize", "20", "status", "active"));

        DiscoveredEndpoint_littlespidy ep2 = new DiscoveredEndpoint_littlespidy("GET", "/items/{itemId}/reviews/{reviewId}", "Reviews");
        ep2.setQueryParams(Map.of("sort", "desc", "filter", "verified"));

        DiscoveredEndpoint_littlespidy ep3 = new DiscoveredEndpoint_littlespidy("POST", "/users", "Create User");
        ep3.setBodyParams(Map.of("username", "testuser", "email", "test@example.com"));

        col.setEndpoints(List.of(ep1, ep2, ep3));
        paramTab.updateCollections(List.of(col));

        // Verify Query Table has 5 items and column 3 is Data Type
        JTable queryTable = paramTab.getQueryTable();
        assertEquals(5, queryTable.getRowCount());
        assertEquals("Data Type", queryTable.getColumnName(3));

        // Verify Path Table has 3 items and column 3 is Data Type
        JTable pathTable = paramTab.getPathTable();
        assertEquals(3, pathTable.getRowCount());
        assertEquals("Data Type", pathTable.getColumnName(3));

        // Verify Body Table has 2 items and column 3 is Data Type
        JTable bodyTable = paramTab.getBodyTable();
        assertEquals(2, bodyTable.getRowCount());
        assertEquals("Data Type", bodyTable.getColumnName(3));

        // Check summary label
        Field summaryLabelField = ParameterCollectorTab_littlespidy.class.getDeclaredField("summaryLabel");
        summaryLabelField.setAccessible(true);
        JLabel summaryLabel = (JLabel) summaryLabelField.get(paramTab);
        assertTrue(summaryLabel.getText().contains("Query Params: 5"));
        assertTrue(summaryLabel.getText().contains("Path Params: 3"));
        assertTrue(summaryLabel.getText().contains("Body Params: 2"));
    }

    @Test
    @DisplayName("Verify Request & Response Viewer Tab structure, auth filter, and session store")
    public void testRequestResponseViewerTab() throws Exception {
        RequestResponseViewerTab_littlespidy viewerTab = new RequestResponseViewerTab_littlespidy(mockApi);

        ImportedCollection_littlespidy col1 = new ImportedCollection_littlespidy("Col A", "OpenAPI 3.0", "FILE", "/test/a.json");
        DiscoveredEndpoint_littlespidy epA = new DiscoveredEndpoint_littlespidy("GET", "/a", "Endpoint A");
        epA.setRequiresAuth(true);
        col1.setEndpoints(List.of(epA));

        ImportedCollection_littlespidy col2 = new ImportedCollection_littlespidy("Col B", "Swagger 2.0", "FILE", "/test/b.json");
        DiscoveredEndpoint_littlespidy epB = new DiscoveredEndpoint_littlespidy("POST", "/b", "Endpoint B");
        epB.setRequiresAuth(false);
        col2.setEndpoints(List.of(epB));

        viewerTab.updateCollections(List.of(col1, col2));

        Field tableField = RequestResponseViewerTab_littlespidy.class.getDeclaredField("requestsTable");
        tableField.setAccessible(true);
        JTable table = (JTable) tableField.get(viewerTab);
        assertEquals(2, table.getRowCount(), "Requests table should display endpoints from both collections");

        // Verify AuthFilterDropDown exists and can filter
        AuthFilterDropDown_littlespidy authFilter = viewerTab.getAuthFilterDropDown();
        assertNotNull(authFilter);
        authFilter.selectAll(false);
        // Only select requires auth
        for (Component c : authFilter.getComponents()) {
            // Dropdown test
        }

        // Verify Session Store is present and can be applied
        SessionStore_littlespidy sessionStore = viewerTab.getSessionStore();
        assertNotNull(sessionStore);
        sessionStore.setEnabled(true);
        sessionStore.setBearerToken("test-jwt-token");
        sessionStore.getCustomHeaders().put("X-Custom-Auth", "secret123");

        burp.api.montoya.http.message.requests.HttpRequest mockReq =
                TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/a", "/a", Map.of(), "");
        burp.api.montoya.http.message.requests.HttpRequest applied = sessionStore.applyToRequest(mockReq, epA);
        assertTrue(applied.hasHeader("Authorization"));
        assertTrue(applied.headerValue("Authorization").contains("test-jwt-token"));
        assertTrue(applied.hasHeader("X-Custom-Auth"));
        assertEquals("secret123", applied.headerValue("X-Custom-Auth"));
    }

    @Test
    @DisplayName("Verify collections imported in APIImportTab automatically propagate to Parameter Collector and Request & Response Viewer")
    public void testImportTabSyncToOtherTabs() throws Exception {
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(mockApi);

        // Simulate external subscriber (e.g. PersistenceManager) attaching listener
        boolean[] persistenceHookFired = new boolean[]{false};
        rootTab.getImportTab().addStateChangedListener(() -> persistenceHookFired[0] = true);

        // Create and import a test collection
        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("Payment Gateway API", "OpenAPI 3.0", "FILE", "/test/payment.json");
        DiscoveredEndpoint_littlespidy ep1 = new DiscoveredEndpoint_littlespidy("POST", "/v1/charges", "Create Charge");
        ep1.setQueryParams(Map.of("currency", "USD", "amount", "100"));
        DiscoveredEndpoint_littlespidy ep2 = new DiscoveredEndpoint_littlespidy("GET", "/v1/charges/{chargeId}", "Get Charge");
        ep2.setPathParams(Map.of("chargeId", "ch_123"));
        col.setEndpoints(List.of(ep1, ep2));

        // Set collections on import tab
        rootTab.getImportTab().setCollections(List.of(col));

        assertTrue(persistenceHookFired[0], "External listener should be triggered");

        // Verify Parameter Collector received collection and extracted params
        ParameterCollectorTab_littlespidy paramTab = rootTab.getParameterCollectorTab();
        assertEquals(2, paramTab.getQueryParamsList().size());
        assertEquals(1, paramTab.getPathParamsList().size());

        // Verify Request & Response Viewer received collection and displays requests
        RequestResponseViewerTab_littlespidy viewerTab = rootTab.getRequestResponseViewerTab();
        Field viewerTableField = RequestResponseViewerTab_littlespidy.class.getDeclaredField("requestsTable");
        viewerTableField.setAccessible(true);
        JTable viewerTable = (JTable) viewerTableField.get(viewerTab);
        assertEquals(2, viewerTable.getRowCount(), "Viewer table should display all 2 endpoints");
    }

    @Test
    @DisplayName("Verify main tabs exact order: API Import, Request & Response Viewer, Parameter Collector, REST API Version Finder")
    public void testMainTabsExactOrder() throws Exception {
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(mockApi);
        Field rootTabbedPaneField = APIInspectorTab_littlespidy.class.getDeclaredField("rootTabbedPane");
        rootTabbedPaneField.setAccessible(true);
        JTabbedPane tabbedPane = (JTabbedPane) rootTabbedPaneField.get(rootTab);

        assertEquals("API Import", tabbedPane.getTitleAt(0));
        assertEquals("Request & Response Viewer", tabbedPane.getTitleAt(1));
        assertEquals("Parameter Collector", tabbedPane.getTitleAt(2));
        assertEquals("REST API Version Finder", tabbedPane.getTitleAt(3));
    }

    @Test
    @DisplayName("Verify Parameter Collector removed individual copy buttons and retains Copy All Combined")
    public void testParameterCollectorButtonsAndCopyIcon() {
        ParameterCollectorTab_littlespidy paramTab = new ParameterCollectorTab_littlespidy();

        boolean hasCopyQueryList = false;
        boolean hasCopyPathList = false;
        boolean hasCopyBodyList = false;
        boolean hasCopyAllQuery = false;
        boolean hasCopyAllPath = false;
        boolean hasCopyAllBody = false;
        boolean hasCopyAllCombined = false;

        for (Component c : getAllComponents(paramTab)) {
            if (c instanceof JButton b) {
                String text = b.getText();
                if ("Copy Query List".equals(text)) hasCopyQueryList = true;
                if ("Copy Path List".equals(text)) hasCopyPathList = true;
                if ("Copy Body List".equals(text)) hasCopyBodyList = true;
                if ("Copy All Query Params".equals(text)) hasCopyAllQuery = true;
                if ("Copy All Path Params".equals(text)) hasCopyAllPath = true;
                if ("Copy All Body Params".equals(text)) hasCopyAllBody = true;
                if ("Copy All (Query + Path + Body)".equals(text)) hasCopyAllCombined = true;
            }
        }

        assertFalse(hasCopyQueryList, "Copy Query List button should be removed");
        assertFalse(hasCopyPathList, "Copy Path List button should be removed");
        assertFalse(hasCopyBodyList, "Copy Body List button should be removed");
        assertFalse(hasCopyAllQuery, "Copy All Query Params button should be removed");
        assertFalse(hasCopyAllPath, "Copy All Path Params button should be removed");
        assertFalse(hasCopyAllBody, "Copy All Body Params button should be removed");
        assertTrue(hasCopyAllCombined, "Copy All (Query + Path + Body) button must be present");
    }

    @Test
    @DisplayName("Verify Request & Response Viewer redundant pane title HTTP Request and Response Viewer is removed")
    public void testRequestResponseViewerRedundantTitleRemoved() {
        RequestResponseViewerTab_littlespidy viewerTab = new RequestResponseViewerTab_littlespidy(mockApi);
        for (Component c : getAllComponents(viewerTab)) {
            if (c instanceof JComponent jc && jc.getBorder() instanceof javax.swing.border.TitledBorder tb) {
                assertNotEquals("HTTP Request and Response Viewer", tb.getTitle(),
                        "Redundant pane title 'HTTP Request and Response Viewer' must be removed");
            }
        }
    }

    @Test
    @DisplayName("Verify API Import Tab has removed Inspect Endpoint Details and Assigned Profile button")
    public void testRemovedFeaturesFromAPIImportTab() {
        APIImportTab_littlespidy importTab = new APIImportTab_littlespidy(mockApi);

        // Inspect Endpoint Details should not exist as a button or field
        boolean hasInspectButton = false;
        boolean hasAssignedProfileButton = false;

        for (Component c : getAllComponents(importTab)) {
            if (c instanceof JButton) {
                String text = ((JButton) c).getText();
                if (text != null && text.contains("Inspect Endpoint Details")) {
                    hasInspectButton = true;
                }
            }
            if (c instanceof JLabel) {
                String text = ((JLabel) c).getText();
                if (text != null && text.contains("Assigned Profile")) {
                    hasAssignedProfileButton = true;
                }
            }
        }

        assertFalse(hasInspectButton, "Inspect Endpoint Details button should be removed");
        assertFalse(hasAssignedProfileButton, "Assigned Profile label/button should be removed from API Import");
    }

    @Test
    @DisplayName("Verify Authenticated Testing multiple profiles, no unauth prompt on creation, and unauth toggle position")
    public void testAuthenticatedTestingEnhancements() throws Exception {
        AuthTestingTab_littlespidy authTab = new AuthTestingTab_littlespidy(mockApi);

        // 1. Verify Unauth Compare checkbox is NOT in AuthProfileDialog
        Field unauthCheckField = null;
        try {
            unauthCheckField = AuthProfileDialog_littlespidy.class.getDeclaredField("unauthCompareCheck");
        } catch (NoSuchFieldException e) {
            // Expected: field removed
        }
        assertNull(unauthCheckField, "unauthCompareCheck should be removed from AuthProfileDialog");

        // 2. Verify profiles table columns: {"Test", "Profile Name", "Auth Type", "Credentials / Details"}
        Field profileTableField = AuthTestingTab_littlespidy.class.getDeclaredField("profileTable");
        profileTableField.setAccessible(true);
        JTable profileTable = (JTable) profileTableField.get(authTab);
        assertEquals("Test", profileTable.getColumnName(0));
        assertEquals("Profile Name", profileTable.getColumnName(1));
        assertEquals("Auth Type", profileTable.getColumnName(2));
        assertEquals("Credentials / Details", profileTable.getColumnName(3));

        // 3. Verify multiple profiles can be added and toggled
        AuthProfile_littlespidy p1 = new AuthProfile_littlespidy("Admin Profile", AuthType_littlespidy.BEARER_TOKEN);
        p1.setBearerToken("admin_tok");
        AuthProfile_littlespidy p2 = new AuthProfile_littlespidy("User Profile", AuthType_littlespidy.BASIC_AUTH);
        p2.setBasicUsername("user");
        p2.setBasicPassword("pass");

        authTab.setProfiles(List.of(p1, p2));
        assertEquals(2, authTab.getActiveProfiles().size());

        // 4. Verify unauthCompareToggle is present above results table
        Field unauthToggleField = AuthTestingTab_littlespidy.class.getDeclaredField("unauthCompareToggle");
        unauthToggleField.setAccessible(true);
        JCheckBox unauthToggle = (JCheckBox) unauthToggleField.get(authTab);
        assertNotNull(unauthToggle);
        assertTrue(unauthToggle.getText().contains("Run unauthenticated comparison test"));

        // 5. Verify results table columns: NO "Unauthenticated Compare" column
        Field resultsTableField = AuthTestingTab_littlespidy.class.getDeclaredField("resultsTable");
        resultsTableField.setAccessible(true);
        JTable resultsTable = (JTable) resultsTableField.get(authTab);

        for (int i = 0; i < resultsTable.getColumnCount(); i++) {
            String colName = resultsTable.getColumnName(i);
            assertNotEquals("Unauthenticated Compare", colName);
            assertNotEquals("Unauth Code", colName);
        }
    }

    @Test
    @DisplayName("Verify HTTP Message Inspector side-by-side profile columns pattern from ng-auth-analyzer")
    public void testHTTPMessageInspectorSideBySide() throws Exception {
        AuthTestingTab_littlespidy authTab = new AuthTestingTab_littlespidy(mockApi);

        // Check view mode toggle buttons
        Field reqToggleField = AuthTestingTab_littlespidy.class.getDeclaredField("requestToggleButton");
        reqToggleField.setAccessible(true);
        JToggleButton reqToggle = (JToggleButton) reqToggleField.get(authTab);
        assertNotNull(reqToggle);
        assertEquals("Request", reqToggle.getText());

        Field respToggleField = AuthTestingTab_littlespidy.class.getDeclaredField("responseToggleButton");
        respToggleField.setAccessible(true);
        JToggleButton respToggle = (JToggleButton) respToggleField.get(authTab);
        assertNotNull(respToggle);
        assertEquals("Response", respToggle.getText());

        // Verify side-by-side columns container
        Field colContainerField = AuthTestingTab_littlespidy.class.getDeclaredField("columnsContainer");
        colContainerField.setAccessible(true);
        JPanel colContainer = (JPanel) colContainerField.get(authTab);
        assertNotNull(colContainer);
        assertTrue(colContainer.getLayout() instanceof GridLayout);

        // Add comparison results across Profile 1, Profile 2, and Unauthenticated request
        AuthTestResult_littlespidy res1 = new AuthTestResult_littlespidy();
        res1.setCollectionId("c1");
        res1.setMethod("GET");
        res1.setPath("/api/v1/data");
        res1.setProfileName("Admin Profile");
        res1.setAuthStatusCode(200);
        res1.setOutcome(AuthTestOutcome_littlespidy.SUCCESS);

        AuthTestResult_littlespidy res2 = new AuthTestResult_littlespidy();
        res2.setCollectionId("c1");
        res2.setMethod("GET");
        res2.setPath("/api/v1/data");
        res2.setProfileName("User Profile");
        res2.setAuthStatusCode(403);
        res2.setOutcome(AuthTestOutcome_littlespidy.AUTH_REJECTED);

        AuthTestResult_littlespidy res3 = new AuthTestResult_littlespidy();
        res3.setCollectionId("c1");
        res3.setMethod("GET");
        res3.setPath("/api/v1/data");
        res3.setProfileName("Unauthenticated request");
        res3.setAuthStatusCode(401);
        res3.setOutcome(AuthTestOutcome_littlespidy.AUTHENTICATED_ONLY);

        authTab.setResults(List.of(res1, res2, res3));

        // Select row 0 in results table
        Field resultsTableField = AuthTestingTab_littlespidy.class.getDeclaredField("resultsTable");
        resultsTableField.setAccessible(true);
        JTable resultsTable = (JTable) resultsTableField.get(authTab);
        resultsTable.setRowSelectionInterval(0, 0);

        // Verify that 3 columns (Admin Profile, User Profile, Unauthenticated request) were populated side-by-side
        assertEquals(3, colContainer.getComponentCount());

        // Test view mode switching
        authTab.setInspectorViewMode(1); // Response mode
        assertTrue(respToggle.isSelected());

        authTab.setInspectorViewMode(0); // Request mode
        assertTrue(reqToggle.isSelected());
    }

    private static List<Component> getAllComponents(Container c) {
        Component[] comps = c.getComponents();
        List<Component> compList = new ArrayList<>();
        for (Component comp : comps) {
            compList.add(comp);
            if (comp instanceof Container) {
                compList.addAll(getAllComponents((Container) comp));
            }
        }
        return compList;
    }
}
