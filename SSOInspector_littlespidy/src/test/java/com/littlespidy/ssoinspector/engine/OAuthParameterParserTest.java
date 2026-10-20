// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.ssoinspector.engine;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class OAuthParameterParserTest {

    @Test
    public void testUrlDecoding() {
        String encoded = "https%3A%2F%2Fapp.example.com%2Fcallback%3Ffoo%3Dbar";
        String decoded = OAuthParameterParser.decodeValue(encoded);
        assertEquals("https://app.example.com/callback?foo=bar", decoded);
    }

    @Test
    public void testJwtDecoding() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"1234567890\",\"name\":\"John Doe\"}".getBytes());
        String signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        String jwt = header + "." + payload + "." + signature;
        String decoded = OAuthParameterParser.decodeValue(jwt);

        assertNotNull(decoded);
        assertTrue(decoded.contains("JWT Header"));
        assertTrue(decoded.contains("JWT Payload"));
        assertTrue(decoded.contains("John Doe"));
    }

    @Test
    public void testEntropyCalculation() {
        // High entropy random string
        double highEntropy = OAuthPassiveAuditEngine.calculateShannonEntropy("c4ca4238a0b923820dcc509a6f75849b");
        assertTrue(highEntropy > 3.0);

        // Low entropy repetitive string
        double lowEntropy = OAuthPassiveAuditEngine.calculateShannonEntropy("1111111111");
        assertEquals(0.0, lowEntropy, 0.001);

        // Sequential short string
        double seqEntropy = OAuthPassiveAuditEngine.calculateShannonEntropy("1234");
        assertTrue(seqEntropy < 2.5);
    }
}
