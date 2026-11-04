// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class JwtTokenHelperTest_littlespidy {

    private String createJwt(Long expEpoch) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payloadJson = expEpoch != null
                ? "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"exp\":" + expEpoch + "}"
                : "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}";
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signature = "fake_signature_hash_value_1234567890";
        return header + "." + payload + "." + signature;
    }

    @Test
    public void testValidJwtWithExpInFuture() {
        long futureExp = Instant.now().getEpochSecond() + 7200; // +2 hours
        String jwt = createJwt(futureExp);
        String header = "Authorization: Bearer " + jwt + "\nContent-Type: application/json";

        JwtTokenHelper_littlespidy.JwtExpirationInfo info = JwtTokenHelper_littlespidy.parse(header);

        assertTrue(info.hasToken());
        assertTrue(info.isJwt());
        assertEquals(jwt.length(), info.tokenLength());
        assertNotNull(info.expEpochSecond());
        assertEquals(futureExp, info.expEpochSecond().longValue());
        assertFalse(info.isExpired());
        assertTrue(info.formattedRemainingTime().contains("h") || info.formattedRemainingTime().contains("m"));
        assertTrue(info.summaryText().contains("Len: " + jwt.length()));
        assertTrue(info.summaryText().contains("Expires in:"));
    }

    @Test
    public void testExpiredJwt() {
        long pastExp = Instant.now().getEpochSecond() - 3600; // -1 hour
        String jwt = createJwt(pastExp);
        String header = "Authorization: Bearer " + jwt;

        JwtTokenHelper_littlespidy.JwtExpirationInfo info = JwtTokenHelper_littlespidy.parse(header);

        assertTrue(info.hasToken());
        assertTrue(info.isJwt());
        assertTrue(info.isExpired());
        assertTrue(info.summaryText().contains("Expired:"));
    }

    @Test
    public void testJwtWithoutExpClaim() {
        String jwt = createJwt(null);
        String header = "Authorization: Bearer " + jwt;

        JwtTokenHelper_littlespidy.JwtExpirationInfo info = JwtTokenHelper_littlespidy.parse(header);

        assertTrue(info.hasToken());
        assertTrue(info.isJwt());
        assertNull(info.expEpochSecond());
        assertFalse(info.isExpired());
        assertTrue(info.summaryText().contains("no exp claim"));
    }

    @Test
    public void testNonJwtBearerToken() {
        String rawToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        String header = "Authorization: Bearer " + rawToken;

        JwtTokenHelper_littlespidy.JwtExpirationInfo info = JwtTokenHelper_littlespidy.parse(header);

        assertTrue(info.hasToken());
        assertFalse(info.isJwt());
        assertEquals(rawToken.length(), info.tokenLength());
        assertTrue(info.summaryText().contains("Non-JWT"));
    }

    @Test
    public void testEmptyAndMalformedHeaders() {
        JwtTokenHelper_littlespidy.JwtExpirationInfo emptyInfo = JwtTokenHelper_littlespidy.parse("");
        assertFalse(emptyInfo.hasToken());

        JwtTokenHelper_littlespidy.JwtExpirationInfo nullInfo = JwtTokenHelper_littlespidy.parse(null);
        assertFalse(nullInfo.hasToken());

        JwtTokenHelper_littlespidy.JwtExpirationInfo noAuthInfo = JwtTokenHelper_littlespidy.parse("Cookie: session=12345\nHost: example.com");
        assertFalse(noAuthInfo.hasToken());
    }
}
