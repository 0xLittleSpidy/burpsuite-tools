// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import burp.api.montoya.MontoyaApi;
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
    @DisplayName("Verify Parameter Collector Tab extracts query and path parameters with separate lines")
    public void testParameterCollectorTab() throws Exception {
        ParameterCollectorTab_littlespidy paramTab = new ParameterCollectorTab_littlespidy();

        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("User API", "OpenAPI 3.0", "FILE", "/test/user.json");
        DiscoveredEndpoint_littlespidy ep1 = new DiscoveredEndpoint_littlespidy("GET", "/users/{userId}/orders", "Get User Orders");
        ep1.setPathParams(Map.of("userId", "123"));
        ep1.setQueryParams(Map.of("page", "1", "pageSize", "20", "status", "active"));

        DiscoveredEndpoint_littlespidy ep2 = new DiscoveredEndpoint_littlespidy("GET", "/items/{itemId}/reviews/{reviewId}", "Reviews");
        ep2.setQueryParams(Map.of("sort", "desc", "filter", "verified"));

        col.setEndpoints(List.of(ep1, ep2));
        paramTab.updateCollections(List.of(col));

        // Check query text area has newline separated query params
        Field queryTextAreaField = ParameterCollectorTab_littlespidy.class.getDeclaredField("queryListTextArea");
        queryTextAreaField.setAccessible(true);
        JTextArea queryArea = (JTextArea) queryTextAreaField.get(paramTab);
        String queryText = queryArea.getText();
        assertTrue(queryText.contains("page\n"));
        assertTrue(queryText.contains("pageSize\n"));
        assertTrue(queryText.contains("status\n"));
        assertTrue(queryText.contains("sort\n"));
        assertTrue(queryText.contains("filter\n"));

        // Check path text area has newline separated path params
        Field pathTextAreaField = ParameterCollectorTab_littlespidy.class.getDeclaredField("pathListTextArea");
        pathTextAreaField.setAccessible(true);
        JTextArea pathArea = (JTextArea) pathTextAreaField.get(paramTab);
        String pathText = pathArea.getText();
        assertTrue(pathText.contains("userId\n"));
        assertTrue(pathText.contains("itemId\n"));
        assertTrue(pathText.contains("reviewId\n"));

        // Check summary label
        Field summaryLabelField = ParameterCollectorTab_littlespidy.class.getDeclaredField("summaryLabel");
        summaryLabelField.setAccessible(true);
        JLabel summaryLabel = (JLabel) summaryLabelField.get(paramTab);
        assertTrue(summaryLabel.getText().contains("Query Params: 5"));
        assertTrue(summaryLabel.getText().contains("Path Params: 3"));
    }

    @Test
    @DisplayName("Verify Request & Response Viewer Tab structure and collection multi-select filter")
    public void testRequestResponseViewerTab() throws Exception {
        RequestResponseViewerTab_littlespidy viewerTab = new RequestResponseViewerTab_littlespidy(mockApi);

        ImportedCollection_littlespidy col1 = new ImportedCollection_littlespidy("Col A", "OpenAPI 3.0", "FILE", "/test/a.json");
        col1.setEndpoints(List.of(new DiscoveredEndpoint_littlespidy("GET", "/a", "Endpoint A")));

        ImportedCollection_littlespidy col2 = new ImportedCollection_littlespidy("Col B", "Swagger 2.0", "FILE", "/test/b.json");
        col2.setEndpoints(List.of(new DiscoveredEndpoint_littlespidy("POST", "/b", "Endpoint B")));

        viewerTab.updateCollections(List.of(col1, col2));

        Field tableField = RequestResponseViewerTab_littlespidy.class.getDeclaredField("requestsTable");
        tableField.setAccessible(true);
        JTable table = (JTable) tableField.get(viewerTab);
        assertEquals(2, table.getRowCount(), "Requests table should display endpoints from both collections");
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
        Field queryAreaField = ParameterCollectorTab_littlespidy.class.getDeclaredField("queryListTextArea");
        queryAreaField.setAccessible(true);
        JTextArea queryArea = (JTextArea) queryAreaField.get(paramTab);
        assertTrue(queryArea.getText().contains("currency\n"), "Query parameters should be present");
        assertTrue(queryArea.getText().contains("amount\n"), "Query parameters should be present");

        Field pathAreaField = ParameterCollectorTab_littlespidy.class.getDeclaredField("pathListTextArea");
        pathAreaField.setAccessible(true);
        JTextArea pathArea = (JTextArea) pathAreaField.get(paramTab);
        assertTrue(pathArea.getText().contains("chargeId\n"), "Path parameters should be present");

        // Verify Request & Response Viewer received collection and displays requests
        RequestResponseViewerTab_littlespidy viewerTab = rootTab.getRequestResponseViewerTab();
        Field viewerTableField = RequestResponseViewerTab_littlespidy.class.getDeclaredField("requestsTable");
        viewerTableField.setAccessible(true);
        JTable viewerTable = (JTable) viewerTableField.get(viewerTab);
        assertEquals(2, viewerTable.getRowCount(), "Viewer table should display all 2 endpoints");
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
