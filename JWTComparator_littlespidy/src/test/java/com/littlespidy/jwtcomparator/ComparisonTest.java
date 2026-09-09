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
}
