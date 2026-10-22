// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.api.SqlmapApiConfig;
import com.littlespidy.sqlmapanalyzer.util.OSUtils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class WindowsPathAndAuthTest_littlespidy {

    @Test
    public void testCleanPath() {
        assertEquals("", OSUtils.cleanPath(null));
        assertEquals("", OSUtils.cleanPath("   "));
        assertEquals("C:\\Python315\\Lib\\site-packages\\sqlmap\\sqlmapapi.py",
                OSUtils.cleanPath("\"C:\\Python315\\Lib\\site-packages\\sqlmap\\sqlmapapi.py\""));
        assertEquals("C:\\Python315\\Lib\\site-packages\\sqlmap\\sqlmapapi.py",
                OSUtils.cleanPath("'C:\\Python315\\Lib\\site-packages\\sqlmap\\sqlmapapi.py'"));
        assertEquals("python", OSUtils.cleanPath("  python  "));
    }

    @Test
    public void testDefaultPythonBinary() {
        String py = OSUtils.getDefaultPythonBinary();
        assertNotNull(py);
        assertTrue(py.equals("python") || py.equals("python3"));
        if (OSUtils.isWindows()) {
            assertEquals("python", py);
        }
    }

    @Test
    public void testConfigDefaultsAndAuth() {
        SqlmapApiConfig config = new SqlmapApiConfig();
        assertEquals("127.0.0.1", config.getHost());
        assertEquals(8775, config.getPort());
        assertEquals("admin", config.getUsername());
        assertEquals("sqlmapapi_pass", config.getPassword());
        assertEquals("http://127.0.0.1:8775", config.getBaseUrl());

        config.setHost("192.168.1.100");
        config.setPort(9000);
        config.setUsername("custom_user");
        config.setPassword("custom_secret");

        assertEquals("192.168.1.100", config.getHost());
        assertEquals(9000, config.getPort());
        assertEquals("custom_user", config.getUsername());
        assertEquals("custom_secret", config.getPassword());
        assertEquals("http://192.168.1.100:9000", config.getBaseUrl());
    }

    @Test
    public void testBasicAuthHeaderGeneration() {
        String username = "admin";
        String password = "sqlmapapi_pass";
        String raw = username + ":" + password;
        String encoded = Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));

        String expectedHeader = "Basic " + encoded;
        assertEquals("Basic YWRtaW46c3FsbWFwYXBpX3Bhc3M=", expectedHeader);

        // Verify roundtrip decoding
        byte[] decodedBytes = Base64.getDecoder().decode(encoded);
        String decoded = new String(decodedBytes, StandardCharsets.UTF_8);
        assertEquals(raw, decoded);
    }

    @Test
    public void testSqlmapApiPathDetectionFormat() {
        String detected = OSUtils.findSqlmapApiPath();
        assertNotNull(detected);
        if (!detected.isBlank()) {
            File f = new File(detected);
            assertTrue(f.exists(), "Detected path should exist if not blank: " + detected);
            assertTrue(detected.endsWith("sqlmapapi.py"), "Detected file should be sqlmapapi.py");
        }
    }
}
