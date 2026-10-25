// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.knowledge;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying scraper parsing and metadata extraction for cookiesearch.org,
 * specifically ensuring ApplicationGatewayAffinity and ai_session are accurately parsed.
 *
 * @author littlespidy
 */
class CookieSearchFetcherTest_littlespidy {

    @Test
    @DisplayName("Verify parsing of ApplicationGatewayAffinity from cookiesearch.org HTML")
    void testParseApplicationGatewayAffinity() {
        String html = """
                <main id="primary" class="site-main single-cookie">
                    <div id="cookie-details">
                        <div class="cookie-details-top">
                            <p class="cname">ApplicationGatewayAffinity</p>
                            <p class="ccat">Necessary</p>
                        </div>
                        <div class="cookie-other-info">
                            <p><span>Cookie ID</span>: &nbsp;ApplicationGatewayAffinity</p>
                            <p><span>URL</span>: &nbsp;</p>
                            <p><span>Category</span>: &nbsp;Necessary</p>
                            <p><span>Script</span>: &nbsp;</p>
                            <p><span>Description</span>:  &nbsp;This cookie is set by the Laravel Framework. This cookie is used for managing browsing sessions. It enables keeping the web browser traffic assigned to single server.</p>
                        </div>
                    </div>
                </main>
                """;

        CookieDocRecord record = CookieSearchFetcher.parseHtml(
                "ApplicationGatewayAffinity",
                "https://www.cookiesearch.org/cookies/?cookie-id=ApplicationGatewayAffinity",
                html
        );

        assertNotNull(record, "Parsed record should not be null");
        assertEquals("ApplicationGatewayAffinity", record.name());
        assertEquals("Necessary", record.category());
        assertEquals("ApplicationGatewayAffinity", record.cookieId());
        assertTrue(record.hasDescription());
        assertTrue(record.description().contains("Laravel Framework"));
        assertTrue(record.description().contains("managing browsing sessions"));
        assertFalse(record.hasUrl());
        assertFalse(record.hasScript());
    }

    @Test
    @DisplayName("Verify parsing of ai_session from cookiesearch.org HTML")
    void testParseAiSession() {
        String html = """
                <main id="primary" class="site-main single-cookie">
                    <div id="cookie-details">
                        <div class="cookie-details-top">
                            <p class="cname">ai_session</p>
                            <p class="ccat">Analytics</p>
                        </div>
                        <div class="cookie-other-info">
                            <p><span>Cookie ID</span>: &nbsp;ai_session</p>
                            <p><span>URL</span>: &nbsp;monitor.azure.com|azureedge.net</p>
                            <p><span>Category</span>: &nbsp;Analytics</p>
                            <p><span>Script</span>: &nbsp;Azure</p>
                            <p><span>Description</span>:  &nbsp;This is a unique anonymous session identifier cookie set by Microsoft Application Insights software to gather statistical usage and telemetry data for apps built on the Azure cloud platform.</p>
                        </div>
                    </div>
                </main>
                """;

        CookieDocRecord record = CookieSearchFetcher.parseHtml(
                "ai_session",
                "https://www.cookiesearch.org/cookies/?cookie-id=ai_session",
                html
        );

        assertNotNull(record, "Parsed record should not be null");
        assertEquals("ai_session", record.name());
        assertEquals("Analytics", record.category());
        assertEquals("ai_session", record.cookieId());
        assertEquals("monitor.azure.com|azureedge.net", record.url());
        assertTrue(record.hasUrl());
        assertEquals("Azure", record.script());
        assertTrue(record.hasScript());
        assertTrue(record.hasDescription());
        assertTrue(record.description().contains("Microsoft Application Insights"));
    }

    @Test
    @DisplayName("Verify fallback heuristics distinguish ai_session from generic session cookies")
    void testFallbackHeuristics() {
        CookieDocRecord aiSessionFallback = CookieSearchFetcher.createInferredOrUnknownRecord("ai_session");
        assertEquals("Analytics", aiSessionFallback.category());
        assertEquals("Azure", aiSessionFallback.script());
        assertTrue(aiSessionFallback.description().contains("Application Insights"));

        CookieDocRecord sessionAuthFallback = CookieSearchFetcher.createInferredOrUnknownRecord("JSESSIONID");
        assertEquals("Necessary", sessionAuthFallback.category());
        assertTrue(sessionAuthFallback.description().contains("application session or authentication identifier"));

        CookieDocRecord affinityFallback = CookieSearchFetcher.createInferredOrUnknownRecord("ApplicationGatewayAffinity");
        assertEquals("Necessary", affinityFallback.category());
        assertTrue(affinityFallback.description().contains("routing affinity"));
    }
}
