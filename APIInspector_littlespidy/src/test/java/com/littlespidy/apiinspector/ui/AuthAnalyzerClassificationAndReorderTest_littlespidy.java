// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.apiinspector.model.AuthProfile_littlespidy;
import com.littlespidy.apiinspector.model.AuthTestOutcome_littlespidy;
import com.littlespidy.apiinspector.model.AuthTestResult_littlespidy;
import com.littlespidy.apiinspector.model.AuthType_littlespidy;
import com.littlespidy.apiinspector.persistence.APIInspectorPersistenceManager_littlespidy;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy.AuthTestResultDTO;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy.SessionRootDTO;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class AuthAnalyzerClassificationAndReorderTest_littlespidy {

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    @Test
    @DisplayName("Verify True Positive and False Positive row marking and clearing")
    public void testClassificationAndRowMarking() {
        AuthTestingTab_littlespidy tab = new AuthTestingTab_littlespidy(null);

        AuthTestResult_littlespidy r1 = new AuthTestResult_littlespidy();
        r1.setCollectionId("col-1");
        r1.setCollectionName("Users API");
        r1.setMethod("GET");
        r1.setPath("/api/v1/users");
        r1.setProfileId("admin-prof");
        r1.setProfileName("Admin");
        r1.setAuthStatusCode(200);

        AuthTestResult_littlespidy r2 = new AuthTestResult_littlespidy();
        r2.setCollectionId("col-1");
        r2.setCollectionName("Users API");
        r2.setMethod("GET");
        r2.setPath("/api/v1/users");
        r2.setProfileId("user-prof");
        r2.setProfileName("Regular User");
        r2.setAuthStatusCode(200);

        tab.setResults(List.of(r1, r2));

        JTable table = getResultsTable(tab);
        assertNotNull(table);
        assertEquals(1, table.getRowCount());

        // Select the row
        table.setRowSelectionInterval(0, 0);

        // Mark as True Positive
        tab.setMarkOnSelectedRows("TRUE_POSITIVE");
        assertEquals("TRUE_POSITIVE", r1.getClassification());
        assertEquals("TRUE_POSITIVE", r2.getClassification());

        List<AuthTestingTab_littlespidy.EndpointResultRow_littlespidy> epRows = tab.getEndpointRows();
        assertEquals(1, epRows.size());
        assertEquals("TRUE_POSITIVE", epRows.get(0).getClassification());

        // Verify renderer applies soft green background for unselected TP row
        table.clearSelection();
        Component c = table.prepareRenderer(table.getCellRenderer(0, 0), 0, 0);
        assertEquals(new Color(220, 248, 224), c.getBackground());

        // Mark as False Positive
        table.setRowSelectionInterval(0, 0);
        tab.setMarkOnSelectedRows("FALSE_POSITIVE");
        assertEquals("FALSE_POSITIVE", r1.getClassification());
        assertEquals("FALSE_POSITIVE", r2.getClassification());
        assertEquals("FALSE_POSITIVE", epRows.get(0).getClassification());

        // Verify renderer applies soft red background for unselected FP row
        table.clearSelection();
        Component cFp = table.prepareRenderer(table.getCellRenderer(0, 0), 0, 0);
        assertEquals(new Color(255, 230, 230), cFp.getBackground());

        // Clear Classification
        table.setRowSelectionInterval(0, 0);
        tab.setMarkOnSelectedRows(null);
        assertNull(r1.getClassification());
        assertNull(r2.getClassification());
        assertNull(epRows.get(0).getClassification());

        // Verify renderer restores default table background and foreground
        table.clearSelection();
        Component cCleared = table.prepareRenderer(table.getCellRenderer(0, 0), 0, 0);
        assertEquals(table.getBackground(), cCleared.getBackground());
        assertEquals(table.getForeground(), cCleared.getForeground());
    }

    @Test
    @DisplayName("Verify no color bleed across adjacent rows when hovering/repainting")
    public void testNoColorBleedAcrossAdjacentRowsOnCursorHover() {
        AuthTestingTab_littlespidy tab = new AuthTestingTab_littlespidy(null);

        // Row 1: Users endpoint
        AuthTestResult_littlespidy r1 = new AuthTestResult_littlespidy();
        r1.setCollectionId("col-1");
        r1.setCollectionName("Users API");
        r1.setMethod("GET");
        r1.setPath("/api/v1/users");
        r1.setProfileId("admin-prof");
        r1.setProfileName("Admin");
        r1.setAuthStatusCode(200);

        // Row 2: Health endpoint (unclassified)
        AuthTestResult_littlespidy r2 = new AuthTestResult_littlespidy();
        r2.setCollectionId("col-1");
        r2.setCollectionName("Users API");
        r2.setMethod("GET");
        r2.setPath("/api/v1/health");
        r2.setProfileId("admin-prof");
        r2.setProfileName("Admin");
        r2.setAuthStatusCode(200);

        tab.setResults(List.of(r1, r2));
        JTable table = getResultsTable(tab);
        assertNotNull(table);
        assertEquals(2, table.getRowCount());

        // Mark only Row 0 as TRUE_POSITIVE
        table.setRowSelectionInterval(0, 0);
        tab.setMarkOnSelectedRows("TRUE_POSITIVE");
        table.clearSelection();

        // Render row 0 (TP) -> must be green
        Component c0 = table.prepareRenderer(table.getCellRenderer(0, 0), 0, 0);
        assertEquals(new Color(220, 248, 224), c0.getBackground());

        // Simulate cursor moving to row 1 (Unclassified) -> must NOT bleed green
        Component c1 = table.prepareRenderer(table.getCellRenderer(1, 0), 1, 0);
        assertEquals(table.getBackground(), c1.getBackground());
        assertEquals(table.getForeground(), c1.getForeground());

        // Mark Row 0 as FALSE_POSITIVE
        table.setRowSelectionInterval(0, 0);
        tab.setMarkOnSelectedRows("FALSE_POSITIVE");
        table.clearSelection();

        // Render row 0 (FP) -> must be red
        Component c0Fp = table.prepareRenderer(table.getCellRenderer(0, 0), 0, 0);
        assertEquals(new Color(255, 230, 230), c0Fp.getBackground());

        // Simulate cursor moving to row 1 (Unclassified) -> must NOT bleed red
        Component c1AfterFp = table.prepareRenderer(table.getCellRenderer(1, 0), 1, 0);
        assertEquals(table.getBackground(), c1AfterFp.getBackground());
        assertEquals(table.getForeground(), c1AfterFp.getForeground());
    }

    @Test
    @DisplayName("Verify ClassificationFilterDropDown matches True Positive, False Positive, and Unclassified rows")
    public void testClassificationFilterDropDownMatching() {
        ClassificationFilterDropDown_littlespidy filterDropDown = new ClassificationFilterDropDown_littlespidy();

        AuthTestingTab_littlespidy.EndpointResultRow_littlespidy rowTp =
                new AuthTestingTab_littlespidy.EndpointResultRow_littlespidy("col-1", "API", "GET", "/tp");
        rowTp.setClassification("TRUE_POSITIVE");

        AuthTestingTab_littlespidy.EndpointResultRow_littlespidy rowFp =
                new AuthTestingTab_littlespidy.EndpointResultRow_littlespidy("col-1", "API", "GET", "/fp");
        rowFp.setClassification("FALSE_POSITIVE");

        AuthTestingTab_littlespidy.EndpointResultRow_littlespidy rowUnclass =
                new AuthTestingTab_littlespidy.EndpointResultRow_littlespidy("col-1", "API", "GET", "/none");
        rowUnclass.setClassification(null);

        // Initially all are selected
        assertTrue(filterDropDown.matches(rowTp));
        assertTrue(filterDropDown.matches(rowFp));
        assertTrue(filterDropDown.matches(rowUnclass));
        assertEquals("Classification: All", filterDropDown.getText());
    }

    @Test
    @DisplayName("Verify Results Table columns follow exact profile order from configured profiles")
    public void testProfileOrderFollowedByColumns() {
        AuthProfile_littlespidy p1 = new AuthProfile_littlespidy("Admin", AuthType_littlespidy.BEARER_TOKEN);
        p1.setId("p1");
        AuthProfile_littlespidy p2 = new AuthProfile_littlespidy("Editor", AuthType_littlespidy.BEARER_TOKEN);
        p2.setId("p2");
        AuthProfile_littlespidy p3 = new AuthProfile_littlespidy("Viewer", AuthType_littlespidy.BEARER_TOKEN);
        p3.setId("p3");

        List<AuthProfile_littlespidy> profiles = new ArrayList<>(List.of(p1, p2, p3));
        Set<String> activeIds = Set.of("p1", "p2", "p3");

        // Initial order
        List<AuthTestingTab_littlespidy.ProfileColumnDef_littlespidy> cols =
                AuthTestingTab_littlespidy.buildDisplayedProfiles(null, profiles, activeIds);

        assertEquals(3, cols.size());
        assertEquals("Admin", cols.get(0).getDisplayName());
        assertEquals("Editor", cols.get(1).getDisplayName());
        assertEquals("Viewer", cols.get(2).getDisplayName());

        // Reorder: Move Viewer to top
        profiles.clear();
        profiles.addAll(List.of(p3, p1, p2));

        List<AuthTestingTab_littlespidy.ProfileColumnDef_littlespidy> reorderedCols =
                AuthTestingTab_littlespidy.buildDisplayedProfiles(null, profiles, activeIds);

        assertEquals(3, reorderedCols.size());
        assertEquals("Viewer", reorderedCols.get(0).getDisplayName());
        assertEquals("Admin", reorderedCols.get(1).getDisplayName());
        assertEquals("Editor", reorderedCols.get(2).getDisplayName());
    }

    @Test
    @DisplayName("Verify Config tab Move Up and Move Down updates profile order and triggers column sync")
    public void testConfigTabMoveUpAndDown() {
        AuthTestingTab_littlespidy testingTab = new AuthTestingTab_littlespidy(null);
        AuthAnalyzerConfigTab_littlespidy configTab = new AuthAnalyzerConfigTab_littlespidy(null, testingTab);
        testingTab.setConfigTab(configTab);

        AuthProfile_littlespidy p1 = new AuthProfile_littlespidy("Alpha", AuthType_littlespidy.BEARER_TOKEN);
        p1.setId("p1");
        AuthProfile_littlespidy p2 = new AuthProfile_littlespidy("Beta", AuthType_littlespidy.BEARER_TOKEN);
        p2.setId("p2");

        configTab.setProfiles(List.of(p1, p2));
        testingTab.onProfilesUpdated();

        assertEquals(2, configTab.getAllProfiles().size());
        assertEquals("Alpha", configTab.getAllProfiles().get(0).getName());
        assertEquals("Beta", configTab.getAllProfiles().get(1).getName());

        // Results table should have Alpha, then Beta
        JTable resultsTable = getResultsTable(testingTab);
        assertNotNull(resultsTable);
        assertEquals(5, resultsTable.getColumnCount());
        assertEquals("Alpha", resultsTable.getColumnName(3));
        assertEquals("Beta", resultsTable.getColumnName(4));

        // Reorder using swap in profiles list
        List<AuthProfile_littlespidy> reordered = new ArrayList<>(List.of(p2, p1));
        configTab.setProfiles(reordered);
        testingTab.onProfilesUpdated();

        assertEquals("Beta", configTab.getAllProfiles().get(0).getName());
        assertEquals("Alpha", configTab.getAllProfiles().get(1).getName());

        assertEquals(5, resultsTable.getColumnCount());
        assertEquals("Beta", resultsTable.getColumnName(3));
        assertEquals("Alpha", resultsTable.getColumnName(4));
    }

    @Test
    @DisplayName("Verify classification serialization and deserialization in SessionStateDTO")
    public void testClassificationPersistence() {
        AuthTestResult_littlespidy res = new AuthTestResult_littlespidy();
        res.setMethod("POST");
        res.setPath("/api/v1/transfer");
        res.setProfileName("Attacker");
        res.setAuthStatusCode(200);
        res.setOutcome(AuthTestOutcome_littlespidy.SUCCESS);
        res.setClassification("TRUE_POSITIVE");

        AuthTestResultDTO dto = APIInspectorPersistenceManager_littlespidy.serializeAuthTestResult(res);
        assertNotNull(dto);
        assertEquals("TRUE_POSITIVE", dto.classification);

        String json = gson.toJson(dto);
        assertTrue(json.contains("\"classification\": \"TRUE_POSITIVE\""));

        AuthTestResultDTO deserializedDto = gson.fromJson(json, AuthTestResultDTO.class);
        AuthTestResult_littlespidy restored = APIInspectorPersistenceManager_littlespidy.deserializeAuthTestResult(deserializedDto);
        assertNotNull(restored);
        assertEquals("TRUE_POSITIVE", restored.getClassification());
        assertEquals("POST", restored.getMethod());
        assertEquals("/api/v1/transfer", restored.getPath());
    }

    private JTable getResultsTable(AuthTestingTab_littlespidy tab) {
        try {
            java.lang.reflect.Field field = AuthTestingTab_littlespidy.class.getDeclaredField("resultsTable");
            field.setAccessible(true);
            return (JTable) field.get(tab);
        } catch (Exception e) {
            fail("Failed to access resultsTable: " + e.getMessage());
            return null;
        }
    }
}
