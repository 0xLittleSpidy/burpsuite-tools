// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import com.littlespidy.sqlmapanalyzer.ui.runner.MultiSelectHeaderDropdown_littlespidy;
import com.littlespidy.sqlmapanalyzer.util.OSUtils;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class HeaderSelectionAndOptionsTest_littlespidy {

    @Test
    public void testParseHeadersFromRawRequest() {
        String raw = "POST /api/v1/users?id=1 HTTP/1.1\r\n" +
                "Host: target.local\r\n" +
                "User-Agent: Mozilla/5.0 TestAgent\r\n" +
                "Authorization: Bearer jwt_test_token_12345\r\n" +
                "Cookie: sessionid=sess_abc123; role=admin\r\n" +
                "Referer: https://target.local/login\r\n" +
                "X-Custom-Token: secret-header-value\r\n" +
                "Content-Type: application/json\r\n" +
                "\r\n" +
                "{\"name\":\"admin\"}";

        Map<String, String> headers = OSUtils.parseHeadersFromRawRequest(raw.getBytes(StandardCharsets.UTF_8));
        assertNotNull(headers);
        assertEquals("target.local", headers.get("Host"));
        assertEquals("Mozilla/5.0 TestAgent", headers.get("User-Agent"));
        assertEquals("Bearer jwt_test_token_12345", headers.get("Authorization"));
        assertEquals("sessionid=sess_abc123; role=admin", headers.get("Cookie"));
        assertEquals("https://target.local/login", headers.get("Referer"));
        assertEquals("secret-header-value", headers.get("X-Custom-Token"));
        assertEquals("application/json", headers.get("Content-Type"));
    }

    @Test
    public void testMultiSelectHeaderDropdownDefaults() {
        MultiSelectHeaderDropdown_littlespidy dropdown = new MultiSelectHeaderDropdown_littlespidy();
        Map<String, String> map = new LinkedHashMap<>();
        map.put("Host", "target.local");
        map.put("Cookie", "PHPSESSID=session_secret_999");
        map.put("Authorization", "Bearer token_xyz");
        map.put("User-Agent", "TestRunner");
        map.put("X-API-Key", "api-key-value-123");

        dropdown.setRequestHeaders(map);

        Set<String> selected = dropdown.getSelectedHeaderNames();
        assertTrue(selected.contains("Cookie"), "Cookie should be auto-selected by default");
        assertTrue(selected.contains("Authorization"), "Authorization should be auto-selected by default");
        assertTrue(selected.contains("X-API-Key"), "API key headers should be auto-selected by default");

        assertEquals("PHPSESSID=session_secret_999", dropdown.getSelectedCookie());

        String headersStr = dropdown.getSelectedHeadersString();
        assertTrue(headersStr.contains("Authorization: Bearer token_xyz"));
        assertTrue(headersStr.contains("X-API-Key: api-key-value-123"));
        assertFalse(headersStr.contains("Cookie:"), "Cookie should be handled via getSelectedCookie(), not extra headers");
    }

    @Test
    public void testSqlmapTaskOptionsCommandLineWithHeadersAndCookies() {
        SqlmapTaskOptions options = new SqlmapTaskOptions();
        options.setUrl("http://target.local/vuln.php?id=1");
        options.setCookie("PHPSESSID=abc123; role=tester");
        options.setAgent("Custom-Scanner/1.0");
        options.setReferer("http://target.local/portal");
        options.setHeaders("Authorization: Bearer token_secret_jwt\nX-CSRF-Token: csrf_abc");

        String cli = options.buildCommandLine();
        assertNotNull(cli);
        assertTrue(cli.contains("--cookie=\"PHPSESSID=abc123; role=tester\""), "CLI must contain --cookie flag");
        assertTrue(cli.contains("--user-agent=\"Custom-Scanner/1.0\""), "CLI must contain --user-agent flag");
        assertTrue(cli.contains("--referer=\"http://target.local/portal\""), "CLI must contain --referer flag");
        assertTrue(cli.contains("--headers=\"Authorization: Bearer token_secret_jwt\\nX-CSRF-Token: csrf_abc\""),
                "CLI must contain --headers flag with escaped newlines");

        // Verify toOptionMap() for REST API
        Map<String, Object> optMap = options.toOptionMap();
        assertEquals("PHPSESSID=abc123; role=tester", optMap.get("cookie"));
        assertEquals("Custom-Scanner/1.0", optMap.get("agent"));
        assertEquals("http://target.local/portal", optMap.get("referer"));
        assertEquals("Authorization: Bearer token_secret_jwt\nX-CSRF-Token: csrf_abc", optMap.get("headers"));
    }

    @Test
    public void testDropdownManualSelectionToggle() {
        MultiSelectHeaderDropdown_littlespidy dropdown = new MultiSelectHeaderDropdown_littlespidy();
        Map<String, String> map = new LinkedHashMap<>();
        map.put("Cookie", "session=1");
        map.put("Authorization", "Bearer 2");
        map.put("X-Custom", "val3");

        dropdown.setRequestHeaders(map);

        // Deselect Cookie, keep Authorization
        dropdown.setSelectedHeaders(Set.of("Authorization"));
        assertEquals("", dropdown.getSelectedCookie());
        assertTrue(dropdown.getSelectedHeadersString().contains("Authorization: Bearer 2"));
        assertFalse(dropdown.getSelectedHeadersString().contains("Cookie:"));

        // Select only Cookie
        dropdown.setSelectedHeaders(Set.of("Cookie"));
        assertEquals("session=1", dropdown.getSelectedCookie());
        assertEquals("", dropdown.getSelectedHeadersString());
    }
}
