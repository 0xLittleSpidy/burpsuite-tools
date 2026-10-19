// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.intruder;

import com.littlespidy.apiinspector.TestMockHelper_littlespidy;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class IntruderStrategiesTest_littlespidy {

    @Test
    public void testDocumentationPathGeneration() {
        String endpoint = "/api/v1/admin";
        List<String> paths = PathVariationGenerator_littlespidy.generateDocumentationPaths(endpoint);

        assertNotNull(paths);
        assertEquals(3, paths.size());
        assertEquals("/api/v1/", paths.get(0));
        assertEquals("/api/", paths.get(1));
        assertEquals("/", paths.get(2));
    }

    @Test
    public void testDocumentationPathGenerationWithTrailingSlash() {
        String endpoint = "/api/v1/admin/";
        List<String> paths = PathVariationGenerator_littlespidy.generateDocumentationPaths(endpoint);

        assertNotNull(paths);
        assertEquals(3, paths.size());
        assertEquals("/api/v1/", paths.get(0));
        assertEquals("/api/", paths.get(1));
        assertEquals("/", paths.get(2));
    }

    @Test
    public void testDocumentationPathGenerationWithQueryParams() {
        String endpoint = "/api/v1/users?filter=admin&limit=10";
        List<String> paths = PathVariationGenerator_littlespidy.generateDocumentationPaths(endpoint);

        assertNotNull(paths);
        assertEquals(3, paths.size());
        assertEquals("/api/v1/?filter=admin&limit=10", paths.get(0));
        assertEquals("/api/?filter=admin&limit=10", paths.get(1));
        assertEquals("/?filter=admin&limit=10", paths.get(2));
    }

    @Test
    public void testDocumentationPathRootAndSingleSegment() {
        List<String> singleSeg = PathVariationGenerator_littlespidy.generateDocumentationPaths("/users");
        assertEquals(1, singleSeg.size());
        assertEquals("/", singleSeg.get(0));

        List<String> rootOnly = PathVariationGenerator_littlespidy.generateDocumentationPaths("/");
        assertEquals(1, rootOnly.size());
        assertEquals("/", rootOnly.get(0));
    }

    @Test
    public void testEndpointDiscoveryPathGeneration() {
        String endpoint = "/api/v1/admin";
        List<String> paths = PathVariationGenerator_littlespidy.generateEndpointDiscoveryPaths(endpoint);

        assertNotNull(paths);
        assertFalse(paths.isEmpty());

        // Must include prefix stripped paths
        assertTrue(paths.contains("/v1/admin"), "Expected prefix stripped /v1/admin");
        assertTrue(paths.contains("/admin"), "Expected prefix stripped /admin");

        // Must include progressive right-to-left trimmed paths
        assertTrue(paths.contains("/api/v1/"), "Expected progressive trimmed /api/v1/");
        assertTrue(paths.contains("/api/"), "Expected progressive trimmed /api/");
        assertTrue(paths.contains("/"), "Expected progressive trimmed /");
    }

    @Test
    public void testAuthHeadersStripping() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Host", "api.example.com");
        headers.put("User-Agent", "Mozilla/5.0");
        headers.put("Authorization", "Bearer eyJhbGciOi...");
        headers.put("X-API-Key", "secret-test-key");
        headers.put("Accept", "application/json");

        HttpRequest original = TestMockHelper_littlespidy.createMockRequest(
                "GET", "https://api.example.com/api/v1/admin", "/api/v1/admin", headers, ""
        );

        HttpRequest unauth = AuthStripper_littlespidy.stripAuthentication(original);
        assertNotNull(unauth);

        // Verification: Auth headers removed
        assertFalse(unauth.hasHeader("Authorization"));
        assertFalse(unauth.hasHeader("X-API-Key"));

        // Verification: Non-auth headers preserved
        assertTrue(unauth.hasHeader("Host"));
        assertEquals("api.example.com", unauth.headerValue("Host"));
        assertTrue(unauth.hasHeader("User-Agent"));
        assertTrue(unauth.hasHeader("Accept"));
        assertEquals("application/json", unauth.headerValue("Accept"));

        // Original request must remain unchanged
        assertTrue(original.hasHeader("Authorization"));
        assertTrue(original.hasHeader("X-API-Key"));
    }

    @Test
    public void testAuthCookiesStrippingWithRetainedCookies() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Host", "api.example.com");
        headers.put("Cookie", "sessionid=xyz123; theme=dark; tracking_id=abc987; token=jwttoken");

        HttpRequest original = TestMockHelper_littlespidy.createMockRequest(
                "GET", "https://api.example.com/api/v1/admin", "/api/v1/admin", headers, ""
        );

        HttpRequest unauth = AuthStripper_littlespidy.stripAuthentication(original);
        assertNotNull(unauth);

        assertTrue(unauth.hasHeader("Cookie"));
        String cookieVal = unauth.headerValue("Cookie");
        assertNotNull(cookieVal);

        // Auth cookies removed
        assertFalse(cookieVal.contains("sessionid"));
        assertFalse(cookieVal.contains("token"));

        // Non-auth cookies preserved
        assertTrue(cookieVal.contains("theme=dark"));
        assertTrue(cookieVal.contains("tracking_id=abc987"));
    }

    @Test
    public void testAuthCookiesStrippingAllRemoved() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Host", "api.example.com");
        headers.put("Cookie", "session=abc; jsessionid=def; connect.sid=ghi");

        HttpRequest original = TestMockHelper_littlespidy.createMockRequest(
                "GET", "https://api.example.com/api/v1/admin", "/api/v1/admin", headers, ""
        );

        HttpRequest unauth = AuthStripper_littlespidy.stripAuthentication(original);
        assertNotNull(unauth);

        // All cookies were auth cookies -> Cookie header should be removed
        assertFalse(unauth.hasHeader("Cookie"));
    }
}
