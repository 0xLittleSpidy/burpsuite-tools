// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.evaluator;

import com.littlespidy.headerinspector.csp.evaluator.CSPBypassEngine_littlespidy.BypassEvaluationResult_littlespidy;
import com.littlespidy.headerinspector.csp.evaluator.CSPBypassEngine_littlespidy.BypassFinding_littlespidy;
import com.littlespidy.headerinspector.csp.evaluator.CSPBypassEngine_littlespidy.ParsedCspSource;
import com.littlespidy.headerinspector.ui.common.MultiSelectFilterButton;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Unit tests verifying CSPBypass techniques engine, wildcard matching,
 * directive parsing, and MultiSelectFilterButton dynamic option updates.
 *
 * @author littlespidy
 */
class CSPBypassAndFeaturesTest_littlespidy {

    @Test
    @DisplayName("Verify CSPBypass database loads 370+ known bypass techniques")
    void testDatabaseLoad() {
        int count = CSPBypassEngine_littlespidy.getDatabaseSize();
        assertTrue(count >= 370, "CSPBypass database should contain at least 370 entries, found: " + count);
    }

    @Test
    @DisplayName("Verify CSPSource parsing handles bare schemes, wildcards, and paths")
    void testSourceParsing() {
        ParsedCspSource s1 = CSPBypassEngine_littlespidy.parseCSPSource("https:");
        assertNotNull(s1);
        assertEquals("https", s1.scheme());
        assertEquals("*", s1.host());
        assertFalse(s1.wildcardSubdomain());

        ParsedCspSource s2 = CSPBypassEngine_littlespidy.parseCSPSource("https://*.google.com/path");
        assertNotNull(s2);
        assertEquals("https", s2.scheme());
        assertEquals("google.com", s2.host());
        assertTrue(s2.wildcardSubdomain());
        assertEquals("/path", s2.pathPrefix());

        ParsedCspSource s3 = CSPBypassEngine_littlespidy.parseCSPSource("ajax.googleapis.com:443");
        assertNotNull(s3);
        assertNull(s3.scheme());
        assertEquals("ajax.googleapis.com", s3.host());
        assertFalse(s3.wildcardSubdomain());
    }

    @Test
    @DisplayName("Verify matching policy flags known Angular and JSONP bypasses")
    void testPolicyEvaluationWithBypasses() {
        String csp = "default-src 'none'; script-src 'self' https://ajax.googleapis.com; object-src 'none'";
        BypassEvaluationResult_littlespidy result = CSPBypassEngine_littlespidy.evaluatePolicy(csp);

        assertNotNull(result);
        assertEquals("script-src", result.effectiveDirective());
        assertTrue(result.count() > 0, "Should detect at least 1 bypass for ajax.googleapis.com");

        boolean foundAngular = result.findings().stream()
                .anyMatch(f -> f.domain().equalsIgnoreCase("ajax.googleapis.com") && f.code().contains("angular"));
        assertTrue(foundAngular, "Should detect Angular bypass on ajax.googleapis.com");
    }

    @Test
    @DisplayName("Verify wildcard host matching detects subdomains")
    void testWildcardSubdomainMatching() {
        String csp = "script-src https://*.amazon.com";
        BypassEvaluationResult_littlespidy result = CSPBypassEngine_littlespidy.evaluatePolicy(csp);

        assertTrue(result.count() > 0, "Should detect subdomains under amazon.com");
        boolean matchesAmazonSubdomain = result.findings().stream()
                .anyMatch(f -> f.domain().contains("amazon.com"));
        assertTrue(matchesAmazonSubdomain, "Findings should contain amazon.com subdomains");
    }

    @Test
    @DisplayName("Verify unsafe-inline alert logic per CSP3 spec")
    void testUnsafeInlineDetection() {
        // Unsafe inline without nonces/hashes -> flagged
        BypassEvaluationResult_littlespidy res1 = CSPBypassEngine_littlespidy.evaluatePolicy("script-src 'self' 'unsafe-inline'");
        assertTrue(res1.hasUnsafeInline());

        // Unsafe inline with nonce -> suppressed per spec
        BypassEvaluationResult_littlespidy res2 = CSPBypassEngine_littlespidy.evaluatePolicy("script-src 'self' 'unsafe-inline' 'nonce-secret123'");
        assertFalse(res2.hasUnsafeInline());

        // Unsafe inline with sha256 -> suppressed per spec
        BypassEvaluationResult_littlespidy res3 = CSPBypassEngine_littlespidy.evaluatePolicy("script-src 'self' 'unsafe-inline' 'sha256-abc123=='");
        assertFalse(res3.hasUnsafeInline());
    }

    @Test
    @DisplayName("Verify database search functionality")
    void testDatabaseSearch() {
        List<BypassFinding_littlespidy> angularResults = CSPBypassEngine_littlespidy.searchDatabase("angular");
        assertFalse(angularResults.isEmpty(), "Should find angular gadgets in database");

        List<BypassFinding_littlespidy> allResults = CSPBypassEngine_littlespidy.searchDatabase("");
        assertEquals(CSPBypassEngine_littlespidy.getDatabaseSize(), allResults.size());
    }

    @Test
    @DisplayName("Verify MultiSelectFilterButton updateOptions dynamically refreshes options and selection")
    void testMultiSelectFilterButtonUpdateOptions() {
        MultiSelectFilterButton button = new MultiSelectFilterButton(
                "Domains",
                List.of("All Domains", "domain-a.com", "domain-b.com"),
                Set.of("domain-a.com"),
                sel -> {}
        );

        assertEquals(Set.of("domain-a.com"), button.getSelected());

        // Update with new options preserving valid selection
        button.updateOptions(List.of("All Domains", "domain-a.com", "domain-c.com", "domain-d.com"));
        assertEquals(Set.of("domain-a.com"), button.getSelected());

        // Update with new options not containing previous selection
        button.updateOptions(List.of("All Domains", "domain-x.com", "domain-y.com"));
        assertTrue(button.getSelected().isEmpty());
    }
}
