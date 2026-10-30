// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.apiinspector.model.CorsTechnique_littlespidy;
import com.littlespidy.apiinspector.model.CorsTestResult_littlespidy;
import com.littlespidy.apiinspector.model.CorsTestResult_littlespidy.CorsSeverity;
import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.EndpointSelectionItem_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationPayloadItem_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationTechnique_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationTestResult_littlespidy;
import com.littlespidy.apiinspector.model.InputValidationTestResult_littlespidy.ValidationSeverity;
import com.littlespidy.apiinspector.model.NaughtyStringsParser_littlespidy;
import com.littlespidy.apiinspector.ui.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for CORS bypass techniques, Input Validation fuzzing engine,
 * parallel viewers (equal size 50/50 split), and the unified Config tab.
 */
public class CorsAndInputValidationTest_littlespidy {

    @Test
    @DisplayName("Verify CORS 29 PortSwigger techniques resolution and default list")
    void testCorsTechniquesGeneration() {
        List<CorsTechnique_littlespidy> techs = CorsTechnique_littlespidy.getDefaultTechniques();
        assertTrue(techs.size() >= 29, "Must include at least 29 CORS bypass techniques");

        CorsTechnique_littlespidy dotUnderscore = techs.stream()
                .filter(t -> t.getId().equals("dot_underscore_dot"))
                .findFirst().orElse(null);
        assertNotNull(dotUnderscore);
        assertNotNull(dotUnderscore.getOriginTemplate(), "Origin template must be populated from JSON");
        assertEquals("https://{base}._.{attacker}", dotUnderscore.getOriginTemplate());
        assertEquals("https://target.corp._.attacker.com",
                dotUnderscore.resolveOrigin("https://target.corp", "attacker.com"));

        CorsTechnique_littlespidy nullOrigin = techs.stream()
                .filter(t -> t.getId().equals("trusted_null"))
                .findFirst().orElse(null);
        assertNotNull(nullOrigin);
        assertEquals("null", nullOrigin.resolveOrigin("https://target.corp", "attacker.com"));

        CorsTechnique_littlespidy safariComma = techs.stream()
                .filter(t -> t.getId().equals("safari_comma"))
                .findFirst().orElse(null);
        assertNotNull(safariComma);
        assertEquals("https://target.corp.,.attacker.com",
                safariComma.resolveOrigin("https://target.corp", "attacker.com"));
    }

    @Test
    @DisplayName("Verify CORS response evaluation severity classifications")
    void testCorsResponseEvaluation() {
        com.littlespidy.apiinspector.TestMockHelper_littlespidy mockHelper = new com.littlespidy.apiinspector.TestMockHelper_littlespidy();
        HttpRequest req = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/api", "/api", java.util.Collections.emptyMap(), "");

        // High: Arbitrary origin reflected with ACAC: true
        java.util.Map<String, String> highHeaders = new java.util.LinkedHashMap<>();
        highHeaders.put("Access-Control-Allow-Origin", "https://evil.com");
        highHeaders.put("Access-Control-Allow-Credentials", "true");
        HttpResponse highResp = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockResponse(200, highHeaders, "{\"data\":\"secret\"}");
        HttpRequestResponse highPair = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockHttpRequestResponse(req, highResp);

        CorsTestResult_littlespidy res1 = CorsEngine_littlespidy.evaluateResponse(
                1, "GET", "example.com", "/api", "https://evil.com", "Test", req, highPair
        );
        assertEquals(CorsSeverity.HIGH, res1.getSeverity());
        assertTrue(res1.isAcacPresent());
        assertEquals("https://evil.com", res1.getReflectedAcao());

        // Medium: Arbitrary origin reflected without credentials
        java.util.Map<String, String> medHeaders = new java.util.LinkedHashMap<>();
        medHeaders.put("Access-Control-Allow-Origin", "https://evil.com");
        HttpResponse medResp = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockResponse(200, medHeaders, "{}");
        HttpRequestResponse medPair = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockHttpRequestResponse(req, medResp);

        CorsTestResult_littlespidy res2 = CorsEngine_littlespidy.evaluateResponse(
                2, "GET", "example.com", "/api", "https://evil.com", "Test", req, medPair
        );
        assertEquals(CorsSeverity.MEDIUM, res2.getSeverity());
        assertFalse(res2.isAcacPresent());

        // Info: Origin not reflected
        HttpResponse infoResp = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockResponse(403, java.util.Collections.emptyMap(), "");
        HttpRequestResponse infoPair = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockHttpRequestResponse(req, infoResp);

        CorsTestResult_littlespidy res3 = CorsEngine_littlespidy.evaluateResponse(
                3, "GET", "example.com", "/api", "https://evil.com", "Test", req, infoPair
        );
        assertEquals(CorsSeverity.INFO, res3.getSeverity());
    }

    @Test
    @DisplayName("Verify Input Validation categories, payloads, and response signatures")
    void testInputValidationTechniquesAndEvaluation() {
        List<InputValidationTechnique_littlespidy> techs = InputValidationTechnique_littlespidy.getDefaultTechniques();
        assertTrue(techs.size() >= 5, "Must provide at least 5 retained vulnerability categories");

        HttpRequest req = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockRequest("GET", "https://example.com/search?q=test", "/search?q=test", java.util.Collections.emptyMap(), "");

        // SQL Injection response with database error triggering 500 status
        HttpResponse sqlResp = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockResponse(
                500, java.util.Collections.emptyMap(),
                "org.postgresql.util.PSQLException: ERROR: syntax error at or near 'UNION'"
        );
        HttpRequestResponse sqlPair = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockHttpRequestResponse(req, sqlResp);

        InputValidationTestResult_littlespidy sqlResult = InputValidationEngine_littlespidy.evaluateFuzzResponse(
                1, "GET", "https://example.com/search?q=test", "q", "BLNS: Reserved Identifiers",
                "' UNION SELECT null--", List.of("syntax error", "psqlexception"), sqlPair
        );
        assertEquals(ValidationSeverity.HIGH, sqlResult.getSeverity());
        assertTrue(sqlResult.getDetectionIndicator().contains("500"));

        // XSS response with unencoded reflection
        HttpResponse xssResp = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockResponse(
                200, java.util.Collections.singletonMap("Content-Type", "text/html"),
                "<html><body>Search results: <script>alert(1)</script></body></html>"
        );
        HttpRequestResponse xssPair = com.littlespidy.apiinspector.TestMockHelper_littlespidy.createMockHttpRequestResponse(req, xssResp);
        InputValidationTestResult_littlespidy xssResult = InputValidationEngine_littlespidy.evaluateFuzzResponse(
                2, "GET", "https://example.com/search?q=test", "q", "BLNS: Special Characters & Quotation Quirks",
                "<script>alert(1)</script>", List.of("not_matched"), xssPair
        );
        assertEquals(ValidationSeverity.MEDIUM, xssResult.getSeverity());
        assertTrue(xssResult.getDetectionIndicator().contains("reflected"));
    }

    @Test
    @DisplayName("Verify CORS and Input Validation runners feature 50/50 parallel split viewers")
    void testParallelViewersEqualSize() throws Exception {
        CorsRunnerPanel_littlespidy corsRunner = new CorsRunnerPanel_littlespidy(null, "r1", "CORS Runner 1");
        Field corsSplitField = CorsRunnerPanel_littlespidy.class.getDeclaredField("parallelViewerSplitPane");
        corsSplitField.setAccessible(true);
        JSplitPane corsSplit = (JSplitPane) corsSplitField.get(corsRunner);
        assertNotNull(corsSplit, "Parallel viewer split pane must exist");
        assertEquals(JSplitPane.HORIZONTAL_SPLIT, corsSplit.getOrientation(), "Orientation must be horizontal (side-by-side)");
        assertEquals(0.5d, corsSplit.getResizeWeight(), 0.001, "Resize weight must be 0.5 (equal size 50/50)");

        InputValidationRunnerPanel_littlespidy fuzzRunner = new InputValidationRunnerPanel_littlespidy(null, "r2", "Input Validation Runner 1");
        Field fuzzSplitField = InputValidationRunnerPanel_littlespidy.class.getDeclaredField("parallelViewerSplitPane");
        fuzzSplitField.setAccessible(true);
        JSplitPane fuzzSplit = (JSplitPane) fuzzSplitField.get(fuzzRunner);
        assertNotNull(fuzzSplit, "Parallel viewer split pane must exist");
        assertEquals(JSplitPane.HORIZONTAL_SPLIT, fuzzSplit.getOrientation(), "Orientation must be horizontal (side-by-side)");
        assertEquals(0.5d, fuzzSplit.getResizeWeight(), 0.001, "Resize weight must be 0.5 (equal size 50/50)");
    }

    @Test
    @DisplayName("Verify ConfigTab sub-tabs: CORS, Input Validation, and Auth Analyzer")
    void testConfigTabSubTabs() {
        AuthTestingTab_littlespidy authTab = new AuthTestingTab_littlespidy(null);
        CorsTab_littlespidy corsTab = new CorsTab_littlespidy(null);
        InputValidationTab_littlespidy inputValTab = new InputValidationTab_littlespidy(null);

        ConfigTab_littlespidy configTab = new ConfigTab_littlespidy(null, authTab, corsTab, inputValTab);

        assertNotNull(configTab.getCorsConfigPanel());
        assertNotNull(configTab.getInputValidationConfigPanel());
        assertNotNull(configTab.getAuthAnalyzerConfigTab());

        assertEquals("https://example.com", configTab.getCorsConfigPanel().getTargetUrl());
        assertEquals("evil.com", configTab.getCorsConfigPanel().getAttackerDomain());
        assertTrue(configTab.getCorsConfigPanel().getTechniques().size() >= 29);

        assertEquals(5, configTab.getInputValidationConfigPanel().getTechniques().size());
    }

    @Test
    @DisplayName("Verify EndpointSelectionTableModel selection, filtering, and toggle")
    void testEndpointSelectionTableModel() {
        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("Test Collection", "OpenAPI 3.0", "FILE", "test.json");
        col.setTargetBaseUrl("https://api.example.com");
        DiscoveredEndpoint_littlespidy ep1 = new DiscoveredEndpoint_littlespidy("GET", "/api/v1/users", "List users");
        DiscoveredEndpoint_littlespidy ep2 = new DiscoveredEndpoint_littlespidy("POST", "/api/v1/login", "User login");
        col.getEndpoints().add(ep1);
        col.getEndpoints().add(ep2);

        EndpointSelectionItem_littlespidy item1 = new EndpointSelectionItem_littlespidy(col, ep1, true);
        EndpointSelectionItem_littlespidy item2 = new EndpointSelectionItem_littlespidy(col, ep2, false);

        EndpointSelectionTableModel_littlespidy model = new EndpointSelectionTableModel_littlespidy();
        model.setItems(List.of(item1, item2));

        assertEquals(2, model.getRowCount());
        assertEquals(5, model.getColumnCount());
        assertEquals(true, model.getValueAt(0, 0));
        assertEquals("GET", model.getValueAt(0, 1));
        assertEquals("/api/v1/users", model.getValueAt(0, 2));

        assertEquals(1, model.getSelectedItems().size());

        // Toggle selection
        model.setValueAt(false, 0, 0);
        assertEquals(false, model.getValueAt(0, 0));
        assertEquals(0, model.getSelectedItems().size());

        // Select all
        model.selectAll(true);
        assertEquals(2, model.getSelectedItems().size());

        // Filter
        model.applyFilter("login");
        assertEquals(1, model.getRowCount());
        assertEquals("/api/v1/login", model.getValueAt(0, 2));

        model.applyFilter("");
        assertEquals(2, model.getRowCount());
    }

    @Test
    @DisplayName("Verify CorsConfigPanel and InputValidationConfigPanel collection sync via ConfigTab")
    void testConfigPanelsCollectionSync() {
        APIImportTab_littlespidy importTab = new APIImportTab_littlespidy(null);
        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy("Sync API", "OpenAPI 3.0", "FILE", "sync.json");
        col.setTargetBaseUrl("https://sync.api.local");
        col.getEndpoints().add(new DiscoveredEndpoint_littlespidy("GET", "/sync/data", "Get sync data"));
        col.getEndpoints().add(new DiscoveredEndpoint_littlespidy("POST", "/sync/submit", "Submit sync data"));
        importTab.getAllCollections().add(col);

        ConfigTab_littlespidy configTab = new ConfigTab_littlespidy(null, null, null, null);
        configTab.setImportTabRef(importTab);
        configTab.refreshCollectionsCombo();

        // Cors panel should have the endpoints available
        CorsConfigPanel_littlespidy corsPanel = configTab.getCorsConfigPanel();
        assertNotNull(corsPanel);

        // Input validation panel should have the individual payloads and endpoints available
        InputValidationConfigPanel_littlespidy inputValPanel = configTab.getInputValidationConfigPanel();
        assertNotNull(inputValPanel);
        assertTrue(inputValPanel.getPayloadItems().size() >= 180);
    }

    @Test
    @DisplayName("Verify ClassificationFilterDropDown and right-click marking on CORS and Input Validation")
    void testClassificationFilterAndMarking() {
        ClassificationFilterDropDown_littlespidy filter = new ClassificationFilterDropDown_littlespidy();
        assertTrue(filter.isTruePositiveSelected());
        assertTrue(filter.isFalsePositiveSelected());
        assertTrue(filter.isUnclassifiedSelected());

        // Test unclassified matching
        assertTrue(filter.matchesClassification(null));
        assertTrue(filter.matchesClassification("Unclassified"));
        assertTrue(filter.matchesClassification("TRUE_POSITIVE"));
        assertTrue(filter.matchesClassification("FALSE_POSITIVE"));

        // Verify CorsTestResult classification setter
        CorsTestResult_littlespidy corsRes = new CorsTestResult_littlespidy(
                1, "GET", "target", "/api", "https://evil.com", "Test",
                "https://evil.com", true, 200, 100, CorsSeverity.HIGH, null
        );
        assertNull(corsRes.getClassification());
        corsRes.setClassification("TRUE_POSITIVE");
        assertEquals("TRUE_POSITIVE", corsRes.getClassification());

        // Verify InputValidationTestResult classification setter
        InputValidationTestResult_littlespidy valRes = new InputValidationTestResult_littlespidy(
                1, "POST", "https://api.com", "q", "Reserved", "null", 200, 50, "Normal",
                ValidationSeverity.INFO, null
        );
        assertNull(valRes.getClassification());
        valRes.setClassification("FALSE_POSITIVE");
        assertEquals("FALSE_POSITIVE", valRes.getClassification());
    }

    @Test
    @DisplayName("Verify CORS techniques successfully deserialize from JSON resource file")
    void testCorsTechniquesLoadedFromJson() {
        List<CorsTechnique_littlespidy> techs = CorsTechnique_littlespidy.getDefaultTechniques();
        assertNotNull(techs, "CORS techniques list must not be null");
        assertEquals(30, techs.size(), "Should load exactly 30 CORS techniques (arbitrary + 29 PortSwigger techniques)");

        // Verify key techniques have their originTemplate property mapped from JSON
        CorsTechnique_littlespidy trustedNull = techs.stream().filter(t -> "trusted_null".equals(t.getId())).findFirst().orElse(null);
        assertNotNull(trustedNull);
        assertEquals("null", trustedNull.getOriginTemplate());

        CorsTechnique_littlespidy subdomainTrust = techs.stream().filter(t -> "trust_subdomain".equals(t.getId())).findFirst().orElse(null);
        assertNotNull(subdomainTrust);
        assertEquals("https://{attacker}.{base}", subdomainTrust.getOriginTemplate());
        assertEquals("https://evil.corp.target.com", subdomainTrust.resolveOrigin("target.com", "evil.corp"));
    }

    @Test
    @DisplayName("Verify Input Validation categories deserialize from JSON resource file")
    void testInputValidationCategoriesLoadedFromJson() {
        List<InputValidationTechnique_littlespidy> categories = NaughtyStringsParser_littlespidy.loadCategoriesMetadata();
        assertNotNull(categories, "Categories metadata must not be null");
        assertEquals(5, categories.size(), "Should contain 5 retained BLNS categories");

        InputValidationTechnique_littlespidy numeric = categories.stream().filter(c -> "blns_numeric".equals(c.getId())).findFirst().orElse(null);
        assertNotNull(numeric);
        assertEquals("BLNS: Numeric Boundaries & Extremes", numeric.getCategory());
        assertFalse(numeric.getErrorSignatures().isEmpty(), "Error signatures must be populated from JSON");
        assertTrue(numeric.getErrorSignatures().contains("NumberFormatException"));
    }
}
