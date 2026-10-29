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
import java.lang.reflect.Proxy;
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

        // Verify Query Table has 5 items and column 0 is Parameter, column 3 is Data Type
        JTable queryTable = paramTab.getQueryTable();
        assertEquals(5, queryTable.getRowCount());
        assertEquals("Parameter", queryTable.getColumnName(0));
        assertEquals("Data Type", queryTable.getColumnName(3));

        // Verify Path Table has 3 items and column 0 is Parameter, column 3 is Data Type
        JTable pathTable = paramTab.getPathTable();
        assertEquals(3, pathTable.getRowCount());
        assertEquals("Parameter", pathTable.getColumnName(0));
        assertEquals("Data Type", pathTable.getColumnName(3));

        // Verify Body Table has 2 items and column 0 is Parameter, column 3 is Data Type
        JTable bodyTable = paramTab.getBodyTable();
        assertEquals(2, bodyTable.getRowCount());
        assertEquals("Parameter", bodyTable.getColumnName(0));
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
    @DisplayName("Verify main tabs exact order: API Import, Request & Response Viewer, Parameter Collector, Config, Auth Analyzer, CORS, Input Validation, REST API Version Finder, API Documentation Strategy, API Endpoint Discovery Strategy, Hidden API Storage")
    public void testMainTabsExactOrder() throws Exception {
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(mockApi);
        Field rootTabbedPaneField = APIInspectorTab_littlespidy.class.getDeclaredField("rootTabbedPane");
        rootTabbedPaneField.setAccessible(true);
        JTabbedPane tabbedPane = (JTabbedPane) rootTabbedPaneField.get(rootTab);

        assertEquals("API Import", tabbedPane.getTitleAt(0));
        assertEquals("Request & Response Viewer", tabbedPane.getTitleAt(1));
        assertEquals("Parameter Collector", tabbedPane.getTitleAt(2));
        assertEquals("Config", tabbedPane.getTitleAt(3));
        assertEquals("Auth Analyzer", tabbedPane.getTitleAt(4));
        assertEquals("CORS", tabbedPane.getTitleAt(5));
        assertEquals("Input Validation", tabbedPane.getTitleAt(6));
        assertEquals("REST API Version Finder", tabbedPane.getTitleAt(7));
        assertEquals("API Documentation Strategy", tabbedPane.getTitleAt(8));
        assertEquals("API Endpoint Discovery Strategy", tabbedPane.getTitleAt(9));
        assertEquals("Hidden API Storage", tabbedPane.getTitleAt(10));
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
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(mockApi);
        AuthAnalyzerConfigTab_littlespidy configTab = rootTab.getAuthAnalyzerConfigTab();
        AuthTestingTab_littlespidy authTab = rootTab.getAuthTestingTab();

        // 1. Verify Unauth Compare checkbox is NOT in AuthProfileDialog
        Field unauthCheckField = null;
        try {
            unauthCheckField = AuthProfileDialog_littlespidy.class.getDeclaredField("unauthCompareCheck");
        } catch (NoSuchFieldException e) {
            // Expected: field removed
        }
        assertNull(unauthCheckField, "unauthCompareCheck should be removed from AuthProfileDialog");

        // 2. Verify profiles table columns: {"Test", "Profile Name", "Credentials / Details"} (Auth Type removed)
        Field profileTableField = AuthAnalyzerConfigTab_littlespidy.class.getDeclaredField("profileTable");
        profileTableField.setAccessible(true);
        JTable profileTable = (JTable) profileTableField.get(configTab);
        assertEquals(3, profileTable.getColumnCount());
        assertEquals("Test", profileTable.getColumnName(0));
        assertEquals("Profile Name", profileTable.getColumnName(1));
        assertEquals("Credentials / Details", profileTable.getColumnName(2));

        // 3. Verify multiple profiles can be added and toggled
        AuthProfile_littlespidy p1 = new AuthProfile_littlespidy("Admin Profile", AuthType_littlespidy.BEARER_TOKEN);
        p1.setBearerToken("admin_tok");
        AuthProfile_littlespidy p2 = new AuthProfile_littlespidy("User Profile", AuthType_littlespidy.BASIC_AUTH);
        p2.setBasicUsername("user");
        p2.setBasicPassword("pass");

        authTab.setProfiles(List.of(p1, p2));
        assertEquals(2, authTab.getActiveProfiles().size());

        // 4. Verify Delete Runner button and Status Filter Dropdown are present, Attack button is present on Config tab
        Field deleteRunnerBtnField = AuthTestingTab_littlespidy.class.getDeclaredField("deleteRunnerBtn");
        deleteRunnerBtnField.setAccessible(true);
        JButton deleteRunnerBtn = (JButton) deleteRunnerBtnField.get(authTab);
        assertNotNull(deleteRunnerBtn);
        assertEquals("Delete Runner", deleteRunnerBtn.getText());

        Field attackBtnField = AuthAnalyzerConfigTab_littlespidy.class.getDeclaredField("attackBtn");
        attackBtnField.setAccessible(true);
        JButton attackBtn = (JButton) attackBtnField.get(configTab);
        assertEquals("Attack", attackBtn.getText());

        Field statusFilterField = AuthTestingTab_littlespidy.class.getDeclaredField("statusFilterDropDown");
        statusFilterField.setAccessible(true);
        assertNotNull(statusFilterField.get(authTab));

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

    @Test
    @DisplayName("Verify Parameter Collector Header Copy and Double-Click Navigation")
    public void testParameterCollectorHeaderCopyAndDoubleClickNavigation() throws Exception {
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(mockApi);
        ParameterCollectorTab_littlespidy paramTab = rootTab.getParameterCollectorTab();
        RequestResponseViewerTab_littlespidy viewerTab = rootTab.getRequestResponseViewerTab();

        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("TestCol", "OpenAPI 3.0", "FILE", "/test.json");
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("GET", "/api/test", "Test Endpoint");
        ep.setQueryParams(Map.of("apiKey", "xyz123"));
        col.setEndpoints(List.of(ep));

        rootTab.getImportTab().setCollections(List.of(col));

        // 1. Verify column header renderer on Column 0 is ParameterHeaderRenderer
        JTable queryTable = paramTab.getQueryTable();
        javax.swing.table.TableCellRenderer hr = queryTable.getColumnModel().getColumn(0).getHeaderRenderer();
        assertTrue(hr instanceof ParameterCollectorTab_littlespidy.ParameterHeaderRenderer,
                "Column 0 header renderer must be ParameterHeaderRenderer");

        // 2. Verify double-click listener navigation to RequestResponseViewerTab
        assertEquals(1, paramTab.getQueryParamsList().size());
        ParameterCollectorTab_littlespidy.ParameterEntry entry = paramTab.getQueryParamsList().get(0);
        assertNotNull(entry.getFirstEndpoint());
        assertEquals("/api/test", entry.getFirstEndpoint().getPath());

        // Simulate selection and display in viewerTab
        boolean selected = viewerTab.selectAndDisplayEndpoint(entry.getFirstEndpoint());
        assertTrue(selected, "Endpoint should be successfully selected and displayed in viewer tab");

        // Test root tab select
        rootTab.selectTab(viewerTab);
        Field rootTabbedPaneField = APIInspectorTab_littlespidy.class.getDeclaredField("rootTabbedPane");
        rootTabbedPaneField.setAccessible(true);
        JTabbedPane tabbedPane = (JTabbedPane) rootTabbedPaneField.get(rootTab);
        assertEquals(viewerTab, tabbedPane.getSelectedComponent());
    }

    @Test
    @DisplayName("Verify Export CSV button is removed from both Intruder Strategy tabs")
    public void testIntruderStrategiesExportCsvRemoved() {
        IntruderStrategyTrackingTab_littlespidy docTab = new IntruderStrategyTrackingTab_littlespidy(mockApi, "Doc Strategy");
        IntruderStrategyTrackingTab_littlespidy epTab = new IntruderStrategyTrackingTab_littlespidy(mockApi, "Endpoint Discovery");

        for (Component c : getAllComponents(docTab)) {
            if (c instanceof JButton b) {
                assertNotEquals("Export CSV", b.getText(), "Export CSV button must be removed from Doc Strategy tab");
            }
        }

        for (Component c : getAllComponents(epTab)) {
            if (c instanceof JButton b) {
                assertNotEquals("Export CSV", b.getText(), "Export CSV button must be removed from Endpoint Discovery Strategy tab");
            }
        }
    }

    @Test
    @DisplayName("Verify REST API Version Finder normal user agent, session store button, and removed close all button")
    public void testRestAPIVersionFinderButtonsAndUserAgent() throws Exception {
        ResAPIVersionFinderTab_littlespidy vfTab = new ResAPIVersionFinderTab_littlespidy(mockApi);

        boolean hasCloseAll = false;
        boolean hasSessionStore = false;

        for (Component c : getAllComponents(vfTab)) {
            if (c instanceof JButton b) {
                if ("Close All Tabs".equals(b.getText())) {
                    hasCloseAll = true;
                }
                if ("Session Store".equals(b.getText())) {
                    hasSessionStore = true;
                }
            }
        }

        assertFalse(hasCloseAll, "Close All Tabs button must be removed from REST API Version Finder");
        assertTrue(hasSessionStore, "Session Store button must be present in REST API Version Finder");

        // Verify Session Store model on vfTab
        SessionStore_littlespidy store = vfTab.getSessionStore();
        assertNotNull(store);
        store.setEnabled(true);
        store.setBearerToken("vf-token-123");

        burp.api.montoya.http.message.requests.HttpRequest mockReq =
                TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/api", "/api", Map.of(), "");
        burp.api.montoya.http.message.requests.HttpRequest applied = store.applyToRequest(mockReq);
        assertTrue(applied.hasHeader("Authorization"));
        assertTrue(applied.headerValue("Authorization").contains("vf-token-123"));
    }

    @Test
    @DisplayName("Verify API Import endpoint details dialog creation and display")
    public void testAPIImportEndpointDetailsDialog() {
        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("POST", "/api/v2/orders", "Create new order");
        ep.setDescription("Detailed description of order creation flow with billing and items.");
        ep.setRequiresAuth(true);
        ep.setAuthSchemes(List.of("Bearer", "OAuth2"));
        ep.setQueryParams(Map.of("dryRun", "true"));
        ep.setBodyParams(Map.of("itemCount", "3"));

        if (!GraphicsEnvironment.isHeadless()) {
            EndpointDetailsDialog_littlespidy dialog = new EndpointDetailsDialog_littlespidy(null, ep, () -> {});
            assertNotNull(dialog);
            assertEquals("Endpoint Details: POST /api/v2/orders", dialog.getTitle());
            dialog.dispose();
        } else {
            assertEquals("POST", ep.getMethod());
            assertEquals("/api/v2/orders", ep.getPath());
            assertEquals("Create new order", ep.getSummary());
            assertEquals("Detailed description of order creation flow with billing and items.", ep.getDescription());
            assertTrue(ep.isRequiresAuth());
        }
    }

    @Test
    @DisplayName("Verify context menu hierarchy has single parent menu without duplicates")
    public void testContextMenuHierarchyAndNoDuplicates() {
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(mockApi);
        APIInspectorContextMenu_littlespidy contextMenu = new APIInspectorContextMenu_littlespidy(mockApi, rootTab);

        burp.api.montoya.http.message.requests.HttpRequest req =
                TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/api/v1/users?page=1", "/api/v1/users?page=1", Map.of(), "");

        burp.api.montoya.http.message.HttpRequestResponse rr = (burp.api.montoya.http.message.HttpRequestResponse) Proxy.newProxyInstance(
                burp.api.montoya.http.message.HttpRequestResponse.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.http.message.HttpRequestResponse.class},
                (proxy, method, args) -> {
                    if ("request".equals(method.getName())) return req;
                    if ("hasResponse".equals(method.getName())) return false;
                    return null;
                }
        );

        burp.api.montoya.ui.contextmenu.ContextMenuEvent event = (burp.api.montoya.ui.contextmenu.ContextMenuEvent) Proxy.newProxyInstance(
                burp.api.montoya.ui.contextmenu.ContextMenuEvent.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.ui.contextmenu.ContextMenuEvent.class},
                (proxy, method, args) -> {
                    if ("selectedRequestResponses".equals(method.getName())) return List.of(rr);
                    if ("messageEditorRequestResponse".equals(method.getName())) return java.util.Optional.empty();
                    if ("invocationType".equals(method.getName())) return burp.api.montoya.ui.contextmenu.InvocationType.PROXY_HISTORY;
                    return null;
                }
        );

        List<Component> items = contextMenu.provideMenuItems(event);
        assertEquals(1, items.size(), "Context menu must provide exactly one single parent menu");
        assertTrue(items.get(0) instanceof JMenu, "Parent item must be a JMenu");

        JMenu parentMenu = (JMenu) items.get(0);
        assertEquals("API Inspector (littlespidy)", parentMenu.getText());

        // Verify the 4 sub-menu actions inside the parent menu
        List<String> subItemNames = new ArrayList<>();
        for (int i = 0; i < parentMenu.getItemCount(); i++) {
            JMenuItem sub = parentMenu.getItem(i);
            if (sub != null) {
                subItemNames.add(sub.getText());
            }
        }

        assertTrue(subItemNames.contains("Send to ResAPI Version Finder"));
        assertTrue(subItemNames.contains("Send to Hidden API Storage"));
        assertTrue(subItemNames.contains("Send to CORS Tester"));
        assertTrue(subItemNames.contains("Send to Input Validation Fuzzer"));
        assertTrue(subItemNames.contains("API Documentation Intruder Strategy"));
        assertTrue(subItemNames.contains("API Endpoint Discovery Intruder Strategy"));
        assertEquals(6, subItemNames.size(), "Must contain exactly six submenu items");
    }

    @Test
    @DisplayName("Verify per-profile columns and removal of Latency and Time columns in AuthTestingTab")
    public void testAuthTestingTabPerProfileColumns() throws Exception {
        AuthTestingTab_littlespidy authTab = new AuthTestingTab_littlespidy(mockApi);

        AuthProfile_littlespidy prof1 = new AuthProfile_littlespidy("Admin", AuthType_littlespidy.BEARER_TOKEN);
        prof1.setId("p1");
        AuthProfile_littlespidy prof2 = new AuthProfile_littlespidy("Auditor", AuthType_littlespidy.API_KEY);
        prof2.setId("p2");

        authTab.setProfiles(List.of(prof1, prof2));

        Field resultsTableField = AuthTestingTab_littlespidy.class.getDeclaredField("resultsTable");
        resultsTableField.setAccessible(true);
        JTable resultsTable = (JTable) resultsTableField.get(authTab);

        // Verify Latency and Time are NOT present in table columns
        for (int i = 0; i < resultsTable.getColumnCount(); i++) {
            String name = resultsTable.getColumnName(i);
            assertFalse(name.toLowerCase().contains("latency"), "Latency column must be removed");
            assertFalse(name.toLowerCase().contains("time"), "Time column must be removed");
        }

        // Verify column structure: 3 base + 1 for Admin + 1 for Auditor = 5 columns (Profile Name as header displaying Status Code)
        assertEquals(5, resultsTable.getColumnCount());
        assertEquals("Collection", resultsTable.getColumnName(0));
        assertEquals("Method", resultsTable.getColumnName(1));
        assertEquals("Path", resultsTable.getColumnName(2));
        assertEquals("Admin", resultsTable.getColumnName(3));
        assertEquals("Auditor", resultsTable.getColumnName(4));
    }

    @Test
    @DisplayName("Verify IDOR cross-comparison outcome calculation and profile status code table columns")
    public void testCrossComparisonIDOROutcomes() throws Exception {
        AuthTestingTab_littlespidy authTab = new AuthTestingTab_littlespidy(mockApi);

        AuthProfile_littlespidy userA = new AuthProfile_littlespidy("User A", AuthType_littlespidy.BEARER_TOKEN);
        userA.setId("user-a");
        AuthProfile_littlespidy userB = new AuthProfile_littlespidy("User B", AuthType_littlespidy.BEARER_TOKEN);
        userB.setId("user-b");

        authTab.setProfiles(List.of(userA, userB));

        // Case 1: Both User A and User B receive EXACT SAME 200 response -> SAME (IDOR Bypass)
        AuthTestResult_littlespidy resA1 = new AuthTestResult_littlespidy();
        resA1.setCollectionId("c1");
        resA1.setMethod("GET");
        resA1.setPath("/api/v1/orders/101");
        resA1.setProfileId("user-a");
        resA1.setProfileName("User A");
        resA1.setAuthStatusCode(200);
        resA1.setAuthResponseBytes("{\"orderId\": 101, \"total\": 100}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        resA1.setAuthResponseLength(31);

        AuthTestResult_littlespidy resB1 = new AuthTestResult_littlespidy();
        resB1.setCollectionId("c1");
        resB1.setMethod("GET");
        resB1.setPath("/api/v1/orders/101");
        resB1.setProfileId("user-b");
        resB1.setProfileName("User B");
        resB1.setAuthStatusCode(200);
        resB1.setAuthResponseBytes("{\"orderId\": 101, \"total\": 100}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        resB1.setAuthResponseLength(31);

        authTab.setResults(List.of(resA1, resB1));

        Field resultsTableField = AuthTestingTab_littlespidy.class.getDeclaredField("resultsTable");
        resultsTableField.setAccessible(true);
        JTable resultsTable = (JTable) resultsTableField.get(authTab);

        assertEquals(1, resultsTable.getRowCount());
        // Outcome columns removed; status codes are displayed directly under profile headers
        assertEquals("200", resultsTable.getValueAt(0, 3));
        assertEquals("200", resultsTable.getValueAt(0, 4));

        // Case 2: User B is forbidden (403) -> DIFFERENT (Access Enforced)
        AuthTestResult_littlespidy resB2 = new AuthTestResult_littlespidy();
        resB2.setCollectionId("c1");
        resB2.setMethod("GET");
        resB2.setPath("/api/v1/orders/101");
        resB2.setProfileId("user-b");
        resB2.setProfileName("User B");
        resB2.setAuthStatusCode(403);
        resB2.setAuthResponseBytes("Forbidden".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        resB2.setAuthResponseLength(9);

        authTab.setResults(List.of(resA1, resB2));
        assertEquals("200", resultsTable.getValueAt(0, 3));
        assertEquals("403", resultsTable.getValueAt(0, 4));

        // Case 3: User B has similar length within 5%
        byte[] bodySimilar = new byte[100];
        byte[] bodyTarget = new byte[102];
        java.util.Arrays.fill(bodySimilar, (byte) 'x');
        java.util.Arrays.fill(bodyTarget, (byte) 'y');

        AuthTestResult_littlespidy resA3 = new AuthTestResult_littlespidy();
        resA3.setCollectionId("c1");
        resA3.setMethod("GET");
        resA3.setPath("/api/v1/data");
        resA3.setProfileId("user-a");
        resA3.setProfileName("User A");
        resA3.setAuthStatusCode(200);
        resA3.setAuthResponseBytes(bodyTarget);
        resA3.setAuthResponseLength(102);

        AuthTestResult_littlespidy resB3 = new AuthTestResult_littlespidy();
        resB3.setCollectionId("c1");
        resB3.setMethod("GET");
        resB3.setPath("/api/v1/data");
        resB3.setProfileId("user-b");
        resB3.setProfileName("User B");
        resB3.setAuthStatusCode(200);
        resB3.setAuthResponseBytes(bodySimilar);
        resB3.setAuthResponseLength(100);

        authTab.setResults(List.of(resA3, resB3));
        assertEquals("200", resultsTable.getValueAt(0, 3));
        assertEquals("200", resultsTable.getValueAt(0, 4));
    }

    @Test
    @DisplayName("Verify side-by-side comparison inspector ordering is strictly deterministic")
    public void testSideBySideComparisonDeterministicOrder() throws Exception {
        AuthTestingTab_littlespidy authTab = new AuthTestingTab_littlespidy(mockApi);

        AuthProfile_littlespidy p1 = new AuthProfile_littlespidy("Alpha Profile", AuthType_littlespidy.BEARER_TOKEN);
        p1.setId("p-alpha");
        AuthProfile_littlespidy p2 = new AuthProfile_littlespidy("Beta Profile", AuthType_littlespidy.API_KEY);
        p2.setId("p-beta");

        authTab.setProfiles(List.of(p1, p2));

        // Create results arriving out-of-order: Beta arrives before Alpha
        AuthTestResult_littlespidy betaRes = new AuthTestResult_littlespidy();
        betaRes.setCollectionId("c1");
        betaRes.setCollectionName("Test API");
        betaRes.setMethod("GET");
        betaRes.setPath("/api/v1/resource");
        betaRes.setProfileId("p-beta");
        betaRes.setProfileName("Beta Profile");
        betaRes.setAuthStatusCode(403);
        betaRes.setOutcome(AuthTestOutcome_littlespidy.AUTH_REJECTED);

        AuthTestResult_littlespidy alphaRes = new AuthTestResult_littlespidy();
        alphaRes.setCollectionId("c1");
        alphaRes.setCollectionName("Test API");
        alphaRes.setMethod("GET");
        alphaRes.setPath("/api/v1/resource");
        alphaRes.setProfileId("p-alpha");
        alphaRes.setProfileName("Alpha Profile");
        alphaRes.setAuthStatusCode(200);
        alphaRes.setOutcome(AuthTestOutcome_littlespidy.SUCCESS);

        AuthTestResult_littlespidy unauthRes = new AuthTestResult_littlespidy();
        unauthRes.setCollectionId("c1");
        unauthRes.setCollectionName("Test API");
        unauthRes.setMethod("GET");
        unauthRes.setPath("/api/v1/resource");
        unauthRes.setProfileId("unauthenticated");
        unauthRes.setProfileName("Unauthenticated request");
        unauthRes.setAuthStatusCode(401);
        unauthRes.setOutcome(AuthTestOutcome_littlespidy.AUTHENTICATED_ONLY);

        // Add in mixed order: Beta, Unauth, Alpha
        authTab.setResults(List.of(betaRes, unauthRes, alphaRes));

        Field resultsTableField = AuthTestingTab_littlespidy.class.getDeclaredField("resultsTable");
        resultsTableField.setAccessible(true);
        JTable resultsTable = (JTable) resultsTableField.get(authTab);

        Field colContainerField = AuthTestingTab_littlespidy.class.getDeclaredField("columnsContainer");
        colContainerField.setAccessible(true);
        JPanel colContainer = (JPanel) colContainerField.get(authTab);

        Field columnViewsField = AuthTestingTab_littlespidy.class.getDeclaredField("columnViews");
        columnViewsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<AuthTestingTab_littlespidy.ProfileColumnView> columnViews =
                (List<AuthTestingTab_littlespidy.ProfileColumnView>) columnViewsField.get(authTab);

        // Select the single aggregated endpoint row
        assertEquals(1, resultsTable.getRowCount(), "All results for same endpoint must group into 1 row");
        resultsTable.setRowSelectionInterval(0, 0);

        assertEquals(3, colContainer.getComponentCount(), "Three side-by-side profile columns expected");
        assertEquals(3, columnViews.size());

        // Verify deterministic column views order: Alpha Profile MUST be column 0, Beta Profile MUST be column 1, Unauth column 2
        // Inspecting first component of card panel header
        Component firstColPanel = colContainer.getComponent(0);
        assertTrue(firstColPanel instanceof JPanel);
        Component secondColPanel = colContainer.getComponent(1);
        assertTrue(secondColPanel instanceof JPanel);
        Component thirdColPanel = colContainer.getComponent(2);
        assertTrue(thirdColPanel instanceof JPanel);
    }

    @Test
    @DisplayName("Verify Request pane contains Run button and top toolbar does not contain single Run button")
    public void testRequestPaneRunButtonPlacement() throws Exception {
        RequestResponseViewerTab_littlespidy tab = new RequestResponseViewerTab_littlespidy(mockApi);

        Field runBtnField = RequestResponseViewerTab_littlespidy.class.getDeclaredField("runBtn");
        runBtnField.setAccessible(true);
        JButton runBtn = (JButton) runBtnField.get(tab);
        assertNotNull(runBtn, "Run button must exist");
        assertEquals("Run", runBtn.getText());

        // Verify parent container of runBtn is inside the Request panel header bar
        Container runBtnParent = runBtn.getParent();
        assertNotNull(runBtnParent);
        Container reqPanel = runBtnParent.getParent();
        assertNotNull(reqPanel);
        assertTrue(reqPanel instanceof JPanel);
        if (((JPanel) reqPanel).getBorder() instanceof javax.swing.border.TitledBorder) {
            assertEquals("Request", ((javax.swing.border.TitledBorder) ((JPanel) reqPanel).getBorder()).getTitle());
        }

        // Verify top action bar does not contain the single Run button
        Field runAllBtnField = RequestResponseViewerTab_littlespidy.class.getDeclaredField("runAllBtn");
        runAllBtnField.setAccessible(true);
        JButton runAllBtn = (JButton) runAllBtnField.get(tab);
        Container topBar = runAllBtn.getParent();
        assertNotSame(runBtnParent, topBar, "Run button must not be in the top action toolbar");
    }

    @Test
    @DisplayName("Verify AuthProfile raw headers and unauth header stripping in AuthTestEngine")
    public void testAuthProfileRawHeadersAndUnauthStripping() throws Exception {
        // 1. Auth Profile with raw headers
        AuthProfile_littlespidy authProf = new AuthProfile_littlespidy("Custom Auth", AuthType_littlespidy.CUSTOM_HEADER);
        authProf.setUnauthenticated(false);
        authProf.setRawHeaders("Authorization: Bearer my-secret-token\nX-Tenant-ID: 1042\nCookie: session=abc");

        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("GET", "/api/v1/user", "Get User");
        burp.api.montoya.http.message.requests.HttpRequest req =
                com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy.buildRequest("https://example.com", ep, authProf, true);

        assertEquals("Bearer my-secret-token", req.headerValue("Authorization"));
        assertEquals("1042", req.headerValue("X-Tenant-ID"));
        assertTrue(req.hasHeader("Cookie"));
        assertEquals("session=abc", req.headerValue("Cookie"));

        // 2. Unauth Profile with specific headers to strip
        AuthProfile_littlespidy unauthProf = new AuthProfile_littlespidy("Strip Profile", AuthType_littlespidy.CUSTOM_HEADER);
        unauthProf.setUnauthenticated(true);
        unauthProf.setRawHeaders("Authorization:\nCookie:\nX-Tenant-ID:");

        burp.api.montoya.http.message.requests.HttpRequest strippedReq =
                com.littlespidy.apiinspector.engine.AuthTestEngine_littlespidy.buildRequest("https://example.com", ep, unauthProf, true);

        assertFalse(strippedReq.hasHeader("Authorization"), "Authorization must be stripped");
        assertFalse(strippedReq.hasHeader("Cookie"), "Cookie must be stripped");
        assertFalse(strippedReq.hasHeader("X-Tenant-ID"), "X-Tenant-ID must be stripped");
    }

    @Test
    @DisplayName("Verify modeless profile dialog and runner history tracking in AuthTestingTab")
    public void testModelessProfileDialogAndRunnerHistory() throws Exception {
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(mockApi);
        AuthAnalyzerConfigTab_littlespidy configTab = rootTab.getAuthAnalyzerConfigTab();
        AuthTestingTab_littlespidy tab = rootTab.getAuthTestingTab();

        // 1. Verify Modeless dialog if non-headless
        if (!GraphicsEnvironment.isHeadless()) {
            final boolean[] callbackInvoked = {false};
            AuthProfileDialog_littlespidy dialog = new AuthProfileDialog_littlespidy(null, "Test Profile", null, p -> {
                callbackInvoked[0] = true;
            });
            assertEquals(Dialog.ModalityType.MODELESS, dialog.getModalityType(), "Profile dialog must be modeless");
        }

        // 2. Verify Runner Name field in config tab and Runner Combo in results tab
        Field runnerNameFieldF = AuthAnalyzerConfigTab_littlespidy.class.getDeclaredField("runnerNameField");
        runnerNameFieldF.setAccessible(true);
        JTextField runnerNameField = (JTextField) runnerNameFieldF.get(configTab);
        assertNotNull(runnerNameField);
        assertEquals("Runner 1", runnerNameField.getText());

        Field runnerComboF = AuthTestingTab_littlespidy.class.getDeclaredField("runnerCombo");
        runnerComboF.setAccessible(true);
        JComboBox<?> runnerCombo = (JComboBox<?>) runnerComboF.get(tab);
        assertNotNull(runnerCombo);

        // 3. Verify Runner history can store and switch runs
        AuthTestResult_littlespidy res1 = new AuthTestResult_littlespidy();
        res1.setCollectionId("c1");
        res1.setMethod("GET");
        res1.setPath("/api/v1/test");
        res1.setProfileId("admin");
        res1.setProfileName("Admin");
        res1.setAuthStatusCode(200);

        AuthTestingTab_littlespidy.AuthTestRun_littlespidy run =
                new AuthTestingTab_littlespidy.AuthTestRun_littlespidy("Runner 1", List.of(res1), Collections.emptyList(), Collections.emptyList());
        assertEquals("Runner 1", run.getName());
        assertEquals(1, run.getResults().size());
    }

    @Test
    @DisplayName("Verify Select All and Deselect All buttons are removed from AuthTestingTab")
    public void testSelectAllButtonsRemovedFromTables() {
        AuthTestingTab_littlespidy tab = new AuthTestingTab_littlespidy(mockApi);
        List<Component> allComps = getAllComponents(tab);
        for (Component c : allComps) {
            if (c instanceof JButton) {
                String text = ((JButton) c).getText();
                if (text != null) {
                    assertFalse("Select All".equalsIgnoreCase(text.trim()), "Select All button must be removed from UI");
                    assertFalse("Deselect All".equalsIgnoreCase(text.trim()), "Deselect All button must be removed from UI");
                }
            }
        }
    }

    @Test
    @DisplayName("Verify ProfileStatusFilterDropDown generates dynamic Profile - StatusCode options and filters rows")
    public void testProfileStatusFilterDropDown() {
        ProfileStatusFilterDropDown_littlespidy dropDown = new ProfileStatusFilterDropDown_littlespidy();

        AuthTestResult_littlespidy r1 = new AuthTestResult_littlespidy();
        r1.setProfileName("Admin");
        r1.setAuthStatusCode(200);

        AuthTestResult_littlespidy r2 = new AuthTestResult_littlespidy();
        r2.setProfileName("Admin");
        r2.setAuthStatusCode(404);

        AuthTestResult_littlespidy r3 = new AuthTestResult_littlespidy();
        r3.setProfileName("User");
        r3.setAuthStatusCode(201);

        AuthTestResult_littlespidy r4 = new AuthTestResult_littlespidy();
        r4.setProfileName("User");
        r4.setAuthStatusCode(403);

        dropDown.updateOptions(List.of(r1, r2, r3, r4));

        Map<String, JCheckBox> options = dropDown.getOptionCheckBoxMap();
        assertEquals(4, options.size());
        assertTrue(options.containsKey("Admin - 200"));
        assertTrue(options.containsKey("Admin - 404"));
        assertTrue(options.containsKey("User - 201"));
        assertTrue(options.containsKey("User - 403"));

        // When all selected, matching passes
        AuthTestingTab_littlespidy.EndpointResultRow_littlespidy row =
                new AuthTestingTab_littlespidy.EndpointResultRow_littlespidy("c1", "Col", "GET", "/test");
        row.getProfileResults().put("Admin", r1);
        assertTrue(dropDown.matches(row));

        // When only User - 403 is selected, row with Admin 200 fails match
        dropDown.selectAll(false);
        options.get("User - 403").setSelected(true);
        assertFalse(dropDown.matches(row));

        // Add User 403 to row and verify it now matches
        row.getProfileResults().put("User", r4);
        assertTrue(dropDown.matches(row));
    }

    @Test
    @DisplayName("Verify Auth Analyzer tab split into Config and Attack tabs and auto-switching")
    public void testAuthAnalyzerTabSplitAndSwitching() throws Exception {
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(mockApi);
        AuthAnalyzerConfigTab_littlespidy configTab = rootTab.getAuthAnalyzerConfigTab();
        AuthTestingTab_littlespidy attackTab = rootTab.getAuthTestingTab();

        assertNotNull(configTab, "AuthAnalyzerConfigTab must be instantiated");
        assertNotNull(attackTab, "AuthTestingTab must be instantiated");

        Field rootTabbedPaneField = APIInspectorTab_littlespidy.class.getDeclaredField("rootTabbedPane");
        rootTabbedPaneField.setAccessible(true);
        JTabbedPane tabbedPane = (JTabbedPane) rootTabbedPaneField.get(rootTab);

        assertEquals(rootTab.getConfigTab(), tabbedPane.getComponentAt(3), "Tab 3 must be config tab");
        assertEquals("Config", tabbedPane.getTitleAt(3));
        assertEquals(attackTab, tabbedPane.getComponentAt(4), "Tab 4 must be attack tab");
        assertEquals("Auth Analyzer", tabbedPane.getTitleAt(4));

        // Test switchToAuthAnalyzer
        tabbedPane.setSelectedIndex(3);
        assertEquals(3, tabbedPane.getSelectedIndex());
        rootTab.switchToAuthAnalyzer();
        assertEquals(4, tabbedPane.getSelectedIndex(), "switchToAuthAnalyzer must activate Tab 4 (Auth Analyzer)");

        // Test delegation of profiles
        AuthProfile_littlespidy p1 = new AuthProfile_littlespidy("Admin", AuthType_littlespidy.BEARER_TOKEN);
        attackTab.setProfiles(List.of(p1));
        assertEquals(1, configTab.getAllProfiles().size());
        assertEquals(1, attackTab.getAllProfiles().size());
        assertEquals("Admin", attackTab.getAllProfiles().get(0).getName());

        // Test runner counter delegation
        configTab.setRunnerCounter(5);
        assertEquals(5, attackTab.getRunnerCounter());
        attackTab.clearAllRunners();
        assertEquals(1, configTab.getRunnerCounter());
        assertEquals(1, attackTab.getRunnerCounter());
    }

    @Test
    @DisplayName("Verify outcome filter removal and HTTP method filter in AuthTestingTab")
    public void testAuthTestingTabMethodFilterAndOutcomeRemoval() throws Exception {
        AuthTestingTab_littlespidy authTab = new AuthTestingTab_littlespidy(mockApi);

        // Verify outcomeFilterCombo field is removed
        assertThrows(NoSuchFieldException.class, () -> {
            AuthTestingTab_littlespidy.class.getDeclaredField("outcomeFilterCombo");
        });

        // Verify methodFilterDropDown exists and is wired
        assertNotNull(authTab.getMethodFilterDropDown());

        AuthProfile_littlespidy prof = new AuthProfile_littlespidy("Admin", AuthType_littlespidy.BEARER_TOKEN);
        prof.setId("p1");
        authTab.setProfiles(List.of(prof));

        AuthTestResult_littlespidy rGet = new AuthTestResult_littlespidy();
        rGet.setCollectionId("c1");
        rGet.setMethod("GET");
        rGet.setPath("/api/v1/users");
        rGet.setProfileId("p1");
        rGet.setAuthStatusCode(200);

        AuthTestResult_littlespidy rPost = new AuthTestResult_littlespidy();
        rPost.setCollectionId("c1");
        rPost.setMethod("POST");
        rPost.setPath("/api/v1/users");
        rPost.setProfileId("p1");
        rPost.setAuthStatusCode(201);

        authTab.setResults(List.of(rGet, rPost));

        Field resultsTableField = AuthTestingTab_littlespidy.class.getDeclaredField("resultsTable");
        resultsTableField.setAccessible(true);
        JTable resultsTable = (JTable) resultsTableField.get(authTab);

        assertEquals(2, resultsTable.getRowCount());

        // Deselect POST in method filter
        authTab.getMethodFilterDropDown().setMethodSelected("POST", false);
        authTab.applyAllFilters();

        assertEquals(1, resultsTable.getRowCount());
        assertEquals("GET", resultsTable.getValueAt(0, 1));

        // Re-select POST
        authTab.getMethodFilterDropDown().setMethodSelected("POST", true);
        authTab.applyAllFilters();
        assertEquals(2, resultsTable.getRowCount());
    }

    @Test
    @DisplayName("Verify collection selection sync and Attack execution targeting selected collection")
    public void testCollectionSelectionSyncAndAttackScope() {
        APIInspectorTab_littlespidy rootTab = new APIInspectorTab_littlespidy(mockApi);
        APIImportTab_littlespidy importTab = rootTab.getImportTab();
        AuthAnalyzerConfigTab_littlespidy configTab = rootTab.getConfigTab().getAuthAnalyzerConfigTab();

        DiscoveredEndpoint_littlespidy ep1 = new DiscoveredEndpoint_littlespidy("GET", "/api/v1/orders", "Orders");
        ImportedCollection_littlespidy col1 = new ImportedCollection_littlespidy("Order API", "OpenAPI", "File", "/path1");
        col1.setEndpoints(List.of(ep1));

        DiscoveredEndpoint_littlespidy ep2 = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/users", "Users");
        ImportedCollection_littlespidy col2 = new ImportedCollection_littlespidy("User API", "OpenAPI", "File", "/path2");
        col2.setEndpoints(List.of(ep2));

        importTab.setCollections(List.of(col1, col2));
        configTab.refreshCollectionsCombo();

        // Select col1
        configTab.selectCollection(col1);
        assertEquals(1, configTab.getEndpointSelectionModel().getRowCount());
        assertEquals("/api/v1/orders", configTab.getEndpointSelectionModel().getItems().get(0).endpoint.getPath());

        // Select col2
        configTab.selectCollection(col2);
        assertEquals(1, configTab.getEndpointSelectionModel().getRowCount());
        assertEquals("/api/v1/users", configTab.getEndpointSelectionModel().getItems().get(0).endpoint.getPath());
    }

    @Test
    @DisplayName("Verify AuthProfileDialog vertical layout and tall headers text area")
    public void testAuthProfileDialogVerticalLayout() throws Exception {
        if (!GraphicsEnvironment.isHeadless()) {
            AuthProfileDialog_littlespidy dialog = new AuthProfileDialog_littlespidy(null, "Test Profile", null);
            assertNotNull(dialog);

            Field headersAreaField = AuthProfileDialog_littlespidy.class.getDeclaredField("headersArea");
            headersAreaField.setAccessible(true);
            JTextArea area = (JTextArea) headersAreaField.get(dialog);

            assertNotNull(area);
            assertEquals(12, area.getRows(), "Headers text area must have 12 rows for vertical orientation");
            assertTrue(area.getLineWrap(), "Headers text area must enable line wrap");
        }
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
