// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.test;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import com.protect7.authanalyzer.gui.dialog.SessionProfileDialog_littlespidy;
import com.protect7.authanalyzer.gui.entity.SessionPanel;
import com.protect7.authanalyzer.gui.convert.ConvertPostToGetPanel_littlespidy;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.gui.main.ConfigurationPanel;
import com.protect7.authanalyzer.util.JwtTokenHelper_littlespidy;

public class SessionProfileAndConvertTest_littlespidy {

    @Test
    public void testJwtTokenParsingAndValidity() {
        long futureEpoch = Instant.now().getEpochSecond() + 3600;
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"sub\":\"user123\",\"exp\":" + futureEpoch + "}";

        String b64Header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String b64Payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String validJwt = b64Header + "." + b64Payload + ".mockSignature";

        String rawHeader = "Authorization: Bearer " + validJwt;
        JwtTokenHelper_littlespidy.JwtExpirationInfo info = JwtTokenHelper_littlespidy.parse(rawHeader);

        assertTrue(info.hasToken());
        assertTrue(info.isJwt());
        assertEquals(validJwt.length(), info.tokenLength());
        assertFalse(info.isExpired());
        assertNotNull(info.expEpochSecond());
        assertEquals(futureEpoch, info.expEpochSecond().longValue());
        assertTrue(info.summaryText().contains("Expires in"));
    }

    @Test
    public void testExpiredJwtTokenParsing() {
        long pastEpoch = Instant.now().getEpochSecond() - 7200;
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"sub\":\"expiredUser\",\"exp\":" + pastEpoch + "}";

        String b64Header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String b64Payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String expiredJwt = b64Header + "." + b64Payload + ".mockSignature";

        String rawHeader = "Authorization: Bearer " + expiredJwt;
        JwtTokenHelper_littlespidy.JwtExpirationInfo info = JwtTokenHelper_littlespidy.parse(rawHeader);

        assertTrue(info.hasToken());
        assertTrue(info.isJwt());
        assertTrue(info.isExpired());
        assertTrue(info.summaryText().contains("Expired"));
    }

    @Test
    public void testOpaqueNonJwtToken() {
        String opaqueToken = "token_abc123_xyz456_secure_random";
        String rawHeader = "Authorization: Bearer " + opaqueToken;
        JwtTokenHelper_littlespidy.JwtExpirationInfo info = JwtTokenHelper_littlespidy.parse(rawHeader);

        assertTrue(info.hasToken());
        assertFalse(info.isJwt());
        assertEquals(opaqueToken.length(), info.tokenLength());
        assertNull(info.expEpochSecond());
        assertTrue(info.summaryText().contains("Non-JWT token"));
    }

    @Test
    public void testSessionProfileDialogModel() {
        SessionPanel panel = new SessionPanel("AdminUser", null);
        panel.setHeadersToReplaceText("Authorization: Bearer test_token\nCookie: session=123");
        panel.setFilterRequestsWithSameHeader(true);
        panel.setRestrictToScope(true);
        panel.setRestrictToScopeText("https://example.com/api");

        if (!java.awt.GraphicsEnvironment.isHeadless()) {
            SessionProfileDialog_littlespidy dialog = new SessionProfileDialog_littlespidy(null, "Test Profile", panel, null);
            assertEquals("AdminUser", dialog.getProfileName());
            assertFalse(dialog.isRemoveHeaders());
            assertTrue(dialog.getHeadersText().contains("Authorization: Bearer test_token"));
            assertTrue(dialog.isFilterRequestsWithSameHeader());
            assertTrue(dialog.isRestrictToScope());
            assertEquals("https://example.com/api", dialog.getScopeUrlText());
        } else {
            assertEquals("AdminUser", panel.getSessionName());
            assertFalse(panel.isRemoveHeaders());
            assertTrue(panel.getHeadersToReplaceText().contains("Authorization: Bearer test_token"));
            assertTrue(panel.isFilterRequestsWithSameHeader());
            assertTrue(panel.isRestrictToScope());
            assertEquals("https://example.com/api", panel.getRestrictToScopeText());
        }
    }
}
