// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.engine;

import com.littlespidy.ssoinspector.export.OAuthReportExporter;
import com.littlespidy.ssoinspector.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class OAuthDataStoreTest {

    @Test
    public void testDataStoreOperations() {
        OAuthDataStore store = new OAuthDataStore();
        assertEquals(0, store.size());

        OAuthRequestEntry entry1 = new OAuthRequestEntry(store.nextId(), null);
        entry1.setFlowType(OAuthFlowType.AUTHORIZATION_CODE_PKCE);
        entry1.setParameters(List.of(
                new OAuthParam("client_id", "client-123", "client-123", OAuthParam.ParamLocation.QUERY, "Client ID", true, false),
                new OAuthParam("redirect_uri", "https://app.example.com/callback", "https://app.example.com/callback", OAuthParam.ParamLocation.QUERY, "Redirect URI", true, false)
        ));

        // Add issue
        entry1.addIssue(new SSOAuditIssue(
                "OAUTHv2/OpenID PKCE Downgraded to Plaintext",
                IssueSeverity.MEDIUM,
                IssueConfidence.FIRM,
                "Test description",
                "Test remediation",
                "RFC 7636",
                null,
                true
        ));

        store.addEntry(entry1);
        assertEquals(1, store.size());
        assertEquals(IssueSeverity.MEDIUM, entry1.getHighestSeverity());
        assertEquals(1, entry1.getIssuesCount());
        assertTrue(entry1.getIssueSummary().contains("PKCE"));

        // Filter tests
        List<OAuthRequestEntry> filteredByFlow = store.getFilteredEntries("", Set.of("Auth Code (PKCE)"), Set.of());
        assertEquals(1, filteredByFlow.size());

        List<OAuthRequestEntry> filteredByOtherFlow = store.getFilteredEntries("", Set.of("Implicit Flow"), Set.of());
        assertEquals(0, filteredByOtherFlow.size());

        List<OAuthRequestEntry> filteredBySeverity = store.getFilteredEntries("", Set.of(), Set.of("Medium"));
        assertEquals(1, filteredBySeverity.size());

        List<OAuthRequestEntry> filteredByHigh = store.getFilteredEntries("", Set.of(), Set.of("High"));
        assertEquals(0, filteredByHigh.size());

        // Report exporter tests
        String markdown = OAuthReportExporter.exportToMarkdown(store.getAllEntries());
        assertNotNull(markdown);
        assertTrue(markdown.contains("SSO Inspector (OAuth) Audit Report"));
        assertTrue(markdown.contains("PKCE Downgraded to Plaintext"));

        String json = OAuthReportExporter.exportToJson(store.getAllEntries());
        assertNotNull(json);
        assertTrue(json.contains("PKCE Downgraded to Plaintext"));
    }
}
