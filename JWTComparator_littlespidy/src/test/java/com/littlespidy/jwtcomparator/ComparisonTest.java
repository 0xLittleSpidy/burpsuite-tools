// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator;

import com.littlespidy.jwtcomparator.model.*;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ComparisonTest {

    private String createTestJwt(String headerJson, String payloadJson) {
        String encHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String encPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return encHeader + "." + encPayload + ".dummy_signature_xyz";
    }

    @Test
    public void testThreeTokenDynamicComparison() {
        // Token 1: api.domain-a.com
        String h1 = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String p1 = "{\"iss\":\"auth.domain-a.com\",\"aud\":\"gateway\",\"role\":\"admin\",\"tenant\":\"us-east\"}";
        JWTTokenModel t1 = new JWTTokenModel(1, "api.domain-a.com");
        JWTParser.parseToken(createTestJwt(h1, p1), t1);

        // Token 2: api.domain-b.com
        String h2 = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String p2 = "{\"iss\":\"auth.domain-b.com\",\"aud\":\"gateway\",\"role\":\"user\",\"tenant\":\"us-east\"}";
        JWTTokenModel t2 = new JWTTokenModel(2, "api.domain-b.com");
        JWTParser.parseToken(createTestJwt(h2, p2), t2);

        // Token 3: api.domain-c.com (Microservice with extra claims and different alg)
        String h3 = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String p3 = "{\"iss\":\"auth.domain-c.com\",\"aud\":\"gateway\",\"role\":\"user\",\"feature_flag\":true}";
        JWTTokenModel t3 = new JWTTokenModel(3, "api.domain-c.com");
        JWTParser.parseToken(createTestJwt(h3, p3), t3);

        ComparisonResult result = ComparisonResult.compute(List.of(t1, t2, t3));

        // Total claims:
        // Header: alg (mismatch: RS256 vs HS256), typ (identical)
        // Payload: iss (mismatch), aud (identical), role (mismatch), tenant (partial: missing in Token 3), feature_flag (partial: only in Token 3)
        // Identical: typ, aud (2 total)
        assertEquals(2, result.getIdenticalCount());

        // Mismatches: alg, iss, role (3 total)
        assertEquals(3, result.getMismatchCount());

        // Partial / Missing: tenant, feature_flag (2 total)
        assertEquals(2, result.getPartialCount());

        // Total: 2 + 3 + 2 = 7
        assertEquals(7, result.getTotalCount());
        assertEquals(5, result.getDifferencesCount());

        // Filter testing: Missing Only
        List<ComparisonRow> missingOnly = result.filter("All", "Missing Only", "");
        assertEquals(2, missingOnly.size());

        // Filter testing: Search query "tenant"
        List<ComparisonRow> searchResult = result.filter("All", "All Claims", "tenant");
        assertEquals(1, searchResult.size());
        assertEquals("tenant", searchResult.get(0).getClaimKey());
    }

    @Test
    public void testTimestampClaimFormatting() {
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        // Exp in future, iat in past
        long now = System.currentTimeMillis() / 1000;
        long exp = now + 3600; // 1 hour in future
        long iat = now - 1800; // 30 min in past

        String payload = String.format("{\"sub\":\"user456\",\"exp\":%d,\"iat\":%d}", exp, iat);
        JWTTokenModel token = new JWTTokenModel(1, "Prod");
        JWTParser.parseToken(createTestJwt(header, payload), token);

        String expStr = token.getTimestampHumanReadable("exp");
        assertNotNull(expStr);
        assertTrue(expStr.contains("Active"));
        assertTrue(expStr.contains("UTC"));

        String iatStr = token.getTimestampHumanReadable("iat");
        assertNotNull(iatStr);
        assertTrue(iatStr.contains("Issued"));
    }

    @Test
    public void testComparisonPanelInitialization() {
        System.setProperty("java.awt.headless", "true");
        com.littlespidy.jwtcomparator.ui.ComparisonPanel panel = new com.littlespidy.jwtcomparator.ui.ComparisonPanel();
        assertNotNull(panel);
    }

    @Test
    public void testTabOrderingWelcomeGuideFirst() {
        System.setProperty("java.awt.headless", "true");
        com.littlespidy.jwtcomparator.ui.JWTComparatorTab tab = new com.littlespidy.jwtcomparator.ui.JWTComparatorTab(null);
        javax.swing.JTabbedPane pane = (javax.swing.JTabbedPane) tab.getComponent(0);
        assertEquals("Welcome & Guide", pane.getTitleAt(0));
        assertEquals("JWT Comparator", pane.getTitleAt(1));
        assertEquals(0, pane.getSelectedIndex()); // Welcome Guide is first and selected by default

        tab.selectComparatorTab();
        assertEquals(1, pane.getSelectedIndex());

        tab.selectWelcomeTab();
        assertEquals(0, pane.getSelectedIndex());
    }

    @Test
    public void testTokenSessionJsonExportAndImport() {
        String h1 = "{\"alg\":\"HS256\"}";
        String p1 = "{\"role\":\"admin\",\"sub\":\"123\"}";
        String jwt1 = createTestJwt(h1, p1);

        String h2 = "{\"alg\":\"RS256\"}";
        String p2 = "{\"role\":\"user\",\"sub\":\"456\"}";
        String jwt2 = createTestJwt(h2, p2);

        JWTTokenModel t1 = new JWTTokenModel(1, "Prod Admin");
        JWTParser.parseToken(jwt1, t1);

        JWTTokenModel t2 = new JWTTokenModel(2, "Staging User");
        JWTParser.parseToken(jwt2, t2);

        String json = TokenSessionManager.exportToJson(List.of(t1, t2));
        assertNotNull(json);
        assertTrue(json.contains("Prod Admin"));
        assertTrue(json.contains("Staging User"));
        assertTrue(json.contains("jwt-comparator") || json.contains("JWT Comparator"));

        List<TokenSessionManager.ExportedToken> imported = TokenSessionManager.importFromJson(json);
        assertEquals(2, imported.size());
        assertEquals("Prod Admin", imported.get(0).getName());
        assertEquals(jwt1, imported.get(0).getRawToken());
        assertEquals("Staging User", imported.get(1).getName());
        assertEquals(jwt2, imported.get(1).getRawToken());
    }

    @Test
    public void testTokenSessionImportVariousJsonFormats() {
        // Format 1: Direct array of token objects
        String arrJson = "[{\"name\":\"Gateway Service\",\"rawToken\":\"dummy.jwt.token1\"},"
                + "{\"name\":\"Auth Server\",\"token\":\"dummy.jwt.token2\"}]";
        List<TokenSessionManager.ExportedToken> res1 = TokenSessionManager.importFromJson(arrJson);
        assertEquals(2, res1.size());
        assertEquals("Gateway Service", res1.get(0).getName());
        assertEquals("dummy.jwt.token1", res1.get(0).getRawToken());
        assertEquals("Auth Server", res1.get(1).getName());
        assertEquals("dummy.jwt.token2", res1.get(1).getRawToken());

        // Format 2: Map of Name -> Token
        String mapJson = "{\"Microservice A\": \"dummy.map.token1\", \"Microservice B\": \"dummy.map.token2\"}";
        List<TokenSessionManager.ExportedToken> res2 = TokenSessionManager.importFromJson(mapJson);
        assertEquals(2, res2.size());
        assertTrue(res2.stream().anyMatch(t -> t.getName().equals("Microservice A") && t.getRawToken().equals("dummy.map.token1")));
        assertTrue(res2.stream().anyMatch(t -> t.getName().equals("Microservice B") && t.getRawToken().equals("dummy.map.token2")));
    }

    @Test
    public void testTsvGenerationAndTokenRenaming() {
        System.setProperty("java.awt.headless", "true");
        com.littlespidy.jwtcomparator.ui.ComparisonPanel panel = new com.littlespidy.jwtcomparator.ui.ComparisonPanel();
        com.littlespidy.jwtcomparator.ui.TokenSlotsContainer slots = panel.getSlotsContainer();

        String h1 = "{\"alg\":\"HS256\"}";
        String p1 = "{\"role\":\"admin\",\"scope\":\"read write\"}";
        String jwt1 = createTestJwt(h1, p1);

        String h2 = "{\"alg\":\"HS256\"}";
        String p2 = "{\"role\":\"guest\",\"scope\":\"read\"}";
        String jwt2 = createTestJwt(h2, p2);

        slots.loadIntoSlot(1, jwt1, "Admin Role");
        slots.loadIntoSlot(2, jwt2, "Guest Role");

        String tsv = panel.generateTsvContent();
        assertNotNull(tsv);
        assertTrue(tsv.contains("Section\tClaim Key"));
        assertTrue(tsv.contains("Token 1 (Admin Role)"));
        assertTrue(tsv.contains("Token 2 (Guest Role)"));
        assertTrue(tsv.contains("Diff Status"));
        assertTrue(tsv.contains("role"));
        assertTrue(tsv.contains("admin"));
        assertTrue(tsv.contains("guest"));
    }

    @Test
    public void testIgnoredClaimsFilterExcludesExpAndIatInDifferencesOnly() {
        String h = "{\"alg\":\"HS256\"}";
        // Token 1: exp=1000, iat=500, role=admin, aud=my-app
        String p1 = "{\"aud\":\"my-app\",\"role\":\"admin\",\"exp\":1000,\"iat\":500}";
        // Token 2: exp=2000, iat=600, role=user, aud=my-app
        String p2 = "{\"aud\":\"my-app\",\"role\":\"user\",\"exp\":2000,\"iat\":600}";

        JWTTokenModel t1 = new JWTTokenModel(1, "Token 1");
        JWTParser.parseToken(createTestJwt(h, p1), t1);

        JWTTokenModel t2 = new JWTTokenModel(2, "Token 2");
        JWTParser.parseToken(createTestJwt(h, p2), t2);

        ComparisonResult result = ComparisonResult.compute(List.of(t1, t2));
        // Total differences without filter: exp, iat, role (3 differences)
        assertEquals(3, result.getDifferencesCount());

        // 1. Unfiltered Differences Only: should return 3 rows (exp, iat, role)
        List<ComparisonRow> unignoredDiffs = result.filter("All", "Differences Only", "");
        assertEquals(3, unignoredDiffs.size());

        // 2. Filter with ignored: exp, iat
        java.util.Set<String> ignored = java.util.Set.of("exp", "iat");
        List<ComparisonRow> filteredDiffs = result.filter("All", "Differences Only", "", ignored);
        assertEquals(1, filteredDiffs.size());
        assertEquals("role", filteredDiffs.get(0).getClaimKey());

        // Verify count of ignored differences
        assertEquals(2, result.countIgnoredDifferences(ignored));

        // 3. In "All Claims" view, exp and iat should still be visible even if in the ignore set
        List<ComparisonRow> allClaims = result.filter("All", "All Claims", "", ignored);
        assertTrue(allClaims.stream().anyMatch(r -> r.getClaimKey().equals("exp")));
        assertTrue(allClaims.stream().anyMatch(r -> r.getClaimKey().equals("iat")));
        assertTrue(allClaims.stream().anyMatch(r -> r.getClaimKey().equals("role")));
        assertTrue(allClaims.stream().anyMatch(r -> r.getClaimKey().equals("aud")));
    }

    @Test
    public void testComparisonPanelIgnoreClaimsFieldAndMethods() {
        System.setProperty("java.awt.headless", "true");
        com.littlespidy.jwtcomparator.ui.ComparisonPanel panel = new com.littlespidy.jwtcomparator.ui.ComparisonPanel();

        // Default ignored keys should be "exp" and "iat"
        java.util.Set<String> initialIgnored = panel.getIgnoredClaimKeys();
        assertTrue(initialIgnored.contains("exp"));
        assertTrue(initialIgnored.contains("iat"));

        // Test addIgnoredClaim
        panel.addIgnoredClaim("jti");
        assertTrue(panel.getIgnoredClaimKeys().contains("jti"));

        // Test removeIgnoredClaim
        panel.removeIgnoredClaim("exp");
        assertFalse(panel.getIgnoredClaimKeys().contains("exp"));
        assertTrue(panel.getIgnoredClaimKeys().contains("iat"));
        assertTrue(panel.getIgnoredClaimKeys().contains("jti"));

        // Test setIgnoredClaims
        panel.setIgnoredClaims(List.of("auth_time", "nbf"));
        assertEquals(2, panel.getIgnoredClaimKeys().size());
        assertTrue(panel.getIgnoredClaimKeys().contains("auth_time"));
        assertTrue(panel.getIgnoredClaimKeys().contains("nbf"));
    }

    @Test
    public void testTokenSessionPreservesIgnoredClaims() {
        String h = "{\"alg\":\"HS256\"}";
        String p = "{\"sub\":\"123\",\"role\":\"tester\"}";
        JWTTokenModel t = new JWTTokenModel(1, "Test Token");
        JWTParser.parseToken(createTestJwt(h, p), t);

        List<String> ignored = List.of("exp", "iat", "jti");
        String json = TokenSessionManager.exportToJson(List.of(t), ignored);

        assertNotNull(json);
        assertTrue(json.contains("ignoredClaims"));
        assertTrue(json.contains("exp"));
        assertTrue(json.contains("iat"));
        assertTrue(json.contains("jti"));

        TokenSessionManager.SessionData sessionData = TokenSessionManager.importSessionFromJson(json);
        assertEquals(1, sessionData.getTokens().size());
        assertEquals(3, sessionData.getIgnoredClaims().size());
        assertTrue(sessionData.getIgnoredClaims().contains("exp"));
        assertTrue(sessionData.getIgnoredClaims().contains("iat"));
        assertTrue(sessionData.getIgnoredClaims().contains("jti"));
    }
}
