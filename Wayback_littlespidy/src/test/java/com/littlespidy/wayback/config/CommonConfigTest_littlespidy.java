// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class CommonConfigTest_littlespidy {

    @Test
    public void testDefaultUserAgentIsRealisticBrowser() {
        CommonConfig_littlespidy config = new CommonConfig_littlespidy();
        assertNotNull(config.getUserAgent());
        assertTrue(config.getUserAgent().contains("Mozilla/5.0"));
        assertTrue(config.getUserAgent().contains("Chrome/"));
        assertFalse(config.getUserAgent().toLowerCase().contains("waybacklister"));
        assertFalse(config.getUserAgent().toLowerCase().contains("bot"));
    }

    @Test
    public void testSignatureMatching() {
        CommonConfig_littlespidy config = new CommonConfig_littlespidy();

        String htmlWithIndex = "<html><head><title>Index of /admin</title></head><body><h1>Index of /admin</h1></body></html>";
        String matched = config.findMatchingSignature(htmlWithIndex);
        assertNotNull(matched);
        assertTrue(matched.equals("Index of /") || matched.equals("<title>Index of"));

        String htmlNormal = "<html><head><title>Welcome to Test Site</title></head><body>Hello world</body></html>";
        assertNull(config.findMatchingSignature(htmlNormal));
    }

    @Test
    public void testAddAndRemoveSignatures() {
        CommonConfig_littlespidy config = new CommonConfig_littlespidy();
        int initialCount = config.getSignatures().size();

        config.addSignature("Directory of C:\\");
        assertEquals(initialCount + 1, config.getSignatures().size());
        assertEquals("Directory of C:\\", config.findMatchingSignature("Directory of C:\\users"));

        config.removeSignature("Directory of C:\\");
        assertEquals(initialCount, config.getSignatures().size());
        assertNull(config.findMatchingSignature("Directory of C:\\users"));
    }
}
