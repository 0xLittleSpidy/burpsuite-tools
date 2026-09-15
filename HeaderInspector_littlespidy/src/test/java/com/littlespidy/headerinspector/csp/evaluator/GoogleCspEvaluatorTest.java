// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.evaluator;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying that Google CSP Evaluator port produces accurate findings.
 */
class GoogleCspEvaluatorTest {

    @Test
    void testScriptUnsafeInlineDetection() {
        String policy = "script-src 'unsafe-inline'; object-src 'none';";
        List<CspFinding> findings = GoogleCspEvaluator.evaluate(policy);

        assertTrue(findings.stream().anyMatch(f ->
            f.type() == CspFindingType.SCRIPT_UNSAFE_INLINE && f.severity() == CspSeverity.HIGH
        ), "Should flag 'unsafe-inline' as HIGH severity");
    }

    @Test
    void testAngularAllowlistBypassDetection() {
        String policy = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; object-src 'none';";
        List<CspFinding> findings = GoogleCspEvaluator.evaluate(policy);

        assertTrue(findings.stream().anyMatch(f ->
            f.type() == CspFindingType.SCRIPT_ALLOWLIST_BYPASS &&
            f.severity() == CspSeverity.HIGH &&
            f.description().contains("cdnjs.cloudflare.com") &&
            f.description().contains("Angular")
        ), "Should identify Angular bypass on cdnjs.cloudflare.com");
    }

    @Test
    void testJsonpAllowlistBypassWithEval() {
        String policy = "default-src 'self'; script-src 'self' https://www.googleapis.com 'unsafe-eval'; object-src 'none';";
        List<CspFinding> findings = GoogleCspEvaluator.evaluate(policy);

        assertTrue(findings.stream().anyMatch(f ->
            f.type() == CspFindingType.SCRIPT_ALLOWLIST_BYPASS &&
            f.severity() == CspSeverity.HIGH &&
            f.description().contains("googleapis.com")
        ), "Should identify JSONP bypass on googleapis.com");
    }

    @Test
    void testMissingObjectSrcDetection() {
        String policy = "script-src 'self'; style-src 'self';";
        List<CspFinding> findings = GoogleCspEvaluator.evaluate(policy);

        assertTrue(findings.stream().anyMatch(f ->
            f.type() == CspFindingType.MISSING_DIRECTIVES &&
            f.severity() == CspSeverity.HIGH &&
            CspModel.DIRECTIVE_OBJECT_SRC.equals(f.directive())
        ), "Should flag missing object-src directive when default-src is absent");
    }

    @Test
    void testMissingSemicolonSyntaxCheck() {
        String policy = "script-src 'self' object-src 'none'";
        List<CspFinding> findings = GoogleCspEvaluator.evaluate(policy);

        assertTrue(findings.stream().anyMatch(f ->
            f.type() == CspFindingType.MISSING_SEMICOLON &&
            f.severity() == CspSeverity.SYNTAX
        ), "Should detect missing semicolon before object-src");
    }

    @Test
    void testInvalidKeywordMissingTicks() {
        String policy = "script-src self; object-src 'none';";
        List<CspFinding> findings = GoogleCspEvaluator.evaluate(policy);

        assertTrue(findings.stream().anyMatch(f ->
            f.type() == CspFindingType.INVALID_KEYWORD &&
            f.severity() == CspSeverity.SYNTAX &&
            "self".equals(f.value())
        ), "Should detect unquoted 'self' keyword");
    }

    @Test
    void testWildcardSourceDetection() {
        String policy = "script-src *; object-src 'none';";
        List<CspFinding> findings = GoogleCspEvaluator.evaluate(policy);

        assertTrue(findings.stream().anyMatch(f ->
            f.type() == CspFindingType.PLAIN_WILDCARD &&
            f.severity() == CspSeverity.HIGH
        ), "Should flag plain wildcard * in script-src");
    }

    @Test
    void testPlainUrlSchemeDetection() {
        String policy = "script-src data: https:; object-src 'none';";
        List<CspFinding> findings = GoogleCspEvaluator.evaluate(policy);

        assertTrue(findings.stream().anyMatch(f ->
            f.type() == CspFindingType.PLAIN_URL_SCHEMES &&
            f.severity() == CspSeverity.HIGH &&
            "data:".equals(f.value())
        ), "Should flag data: URI scheme in script-src");
    }

    @Test
    void testMissingCspHandling() {
        List<CspFinding> findings = GoogleCspEvaluator.evaluate("(missing CSP)");
        assertFalse(findings.isEmpty());
        assertEquals(CspSeverity.HIGH, findings.get(0).severity());
    }

    @Test
    void testUpdateCheckerVersionComparison() {
        assertTrue(GoogleCspUpdateChecker.isNewerVersion("v1.2.0", "v1.1.8"));
        assertTrue(GoogleCspUpdateChecker.isNewerVersion("v1.1.9", "v1.1.8"));
        assertTrue(GoogleCspUpdateChecker.isNewerVersion("v2.0.0", "v1.1.8"));
        assertFalse(GoogleCspUpdateChecker.isNewerVersion("v1.1.8", "v1.1.8"));
        assertFalse(GoogleCspUpdateChecker.isNewerVersion("v1.1.7", "v1.1.8"));
        assertFalse(GoogleCspUpdateChecker.isNewerVersion("1.0.0", "1.1.8"));
    }

    @Test
    void testUpdateCheckerExecution() {
        GoogleCspUpdateChecker.CheckResult result = GoogleCspUpdateChecker.performCheck();
        assertNotNull(result);
        assertEquals(GoogleCspUpdateChecker.EMBEDDED_VERSION, result.embeddedVersion());
        // If network is available, check succeeds and finds v1.1.8
        if (result.success()) {
            assertEquals("v1.1.8", result.latestVersion());
            assertFalse(result.updateAvailable(), "v1.1.8 should be up to date with current Google release");
        }
    }
}
