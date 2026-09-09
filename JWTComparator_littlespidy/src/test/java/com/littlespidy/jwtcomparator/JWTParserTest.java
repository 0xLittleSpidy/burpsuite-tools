// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator;

import com.littlespidy.jwtcomparator.model.*;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class JWTParserTest {

    private String createTestJwt(String headerJson, String payloadJson) {
        String encHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String encPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return encHeader + "." + encPayload + ".dummy_signature_12345";
    }

    @Test
    public void testParseValidToken() {
        String header = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"key-1\"}";
        String payload = "{\"sub\":\"admin_user\",\"iss\":\"https://auth.example.com\",\"aud\":\"api-service\",\"exp\":1893456000,\"roles\":[\"admin\",\"auditor\"]}";
        String jwt = createTestJwt(header, payload);

        JWTTokenModel model = new JWTTokenModel(1, "Test Token");
        boolean success = JWTParser.parseToken(jwt, model);

        assertTrue(success, "Token parsing should succeed");
        assertTrue(model.isValid());
        assertEquals("RS256", model.getAlgorithm());
        assertEquals("https://auth.example.com", model.getIssuer());
        assertEquals("admin_user", model.getSubject());
        assertEquals("api-service", model.getAudience());
        assertEquals("key-1", model.getHeaderClaims().get("kid"));
        assertTrue(model.getPayloadClaims().containsKey("roles"));
        assertNotNull(model.getTimestampHumanReadable("exp"));
    }

    @Test
    public void testParseBearerPrefixHandling() {
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"12345\"}";
        String jwt = "Bearer " + createTestJwt(header, payload);

        JWTTokenModel model = new JWTTokenModel(1, "Bearer Token");
        boolean success = JWTParser.parseToken(jwt, model);

        assertTrue(success);
        assertTrue(model.isValid());
        assertEquals("12345", model.getSubject());
    }

    @Test
    public void testExtractTokenFromText() {
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"99999\"}";
        String jwt = createTestJwt(header, payload);

        String sampleText = "Random log line with Authorization: Bearer " + jwt + " and extra data";
        String extracted = JWTParser.extractTokenFromText(sampleText);

        assertNotNull(extracted);
        assertEquals(jwt, extracted);
    }

    @Test
    public void testMultiTokenComparison() {
        // Token 1: Domain A
        String h1 = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String p1 = "{\"iss\":\"https://domain-a.com\",\"aud\":\"core\",\"sub\":\"user1\",\"role\":\"user\"}";
        JWTTokenModel t1 = new JWTTokenModel(1, "Domain A");
        JWTParser.parseToken(createTestJwt(h1, p1), t1);

        // Token 2: Domain B
        String h2 = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String p2 = "{\"iss\":\"https://domain-b.com\",\"aud\":\"core\",\"sub\":\"user1\",\"role\":\"admin\",\"extra\":\"true\"}";
        JWTTokenModel t2 = new JWTTokenModel(2, "Domain B");
        JWTParser.parseToken(createTestJwt(h2, p2), t2);

        ComparisonResult result = ComparisonResult.compute(List.of(t1, t2));

        // alg, typ, aud, sub are identical across both tokens (4 total)
        assertEquals(4, result.getIdenticalCount());
        // iss, role differ (2 total)
        assertEquals(2, result.getMismatchCount());
        // extra is only in Token 2 (1 total)
        assertEquals(1, result.getPartialCount());
        // Total claims = 4 + 2 + 1 = 7
        assertEquals(7, result.getTotalCount());

        List<ComparisonRow> diffsOnly = result.filter("All", "Differences Only", "");
        assertEquals(3, diffsOnly.size());
        assertTrue(diffsOnly.stream().allMatch(ComparisonRow::isDifference));
    }
}
