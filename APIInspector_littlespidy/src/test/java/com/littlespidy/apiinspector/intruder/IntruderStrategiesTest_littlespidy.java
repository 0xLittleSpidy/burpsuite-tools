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
        String endpoint = "/api/admin/health";
        List<String> paths = PathVariationGenerator_littlespidy.generateEndpointDiscoveryPaths(endpoint);

        assertNotNull(paths);
        assertEquals(3, paths.size(), "Expected exactly 3 parent-path candidates");

        // Verify parent endpoint paths generated from right to left
        assertEquals("/api/admin", paths.get(0));
        assertEquals("/api", paths.get(1));
        assertEquals("/", paths.get(2));

        // Verify total requests when authenticated and unauthenticated are enabled (3 * 2 = 6 requests)
        int totalRequests = paths.size() * 2;
        assertEquals(6, totalRequests, "Expected exactly 6 total requests for 3 parent candidates");
    }

    @Test
    public void testEndpointDiscoveryEdgeCases() {
        // Single segment
        List<String> singleSeg = PathVariationGenerator_littlespidy.generateEndpointDiscoveryPaths("/users");
        assertEquals(1, singleSeg.size());
        assertEquals("/", singleSeg.get(0));

        // Root only
        List<String> rootOnly = PathVariationGenerator_littlespidy.generateEndpointDiscoveryPaths("/");
        assertEquals(1, rootOnly.size());
        assertEquals("/", rootOnly.get(0));

        // Trailing slash
        List<String> trailingSlash = PathVariationGenerator_littlespidy.generateEndpointDiscoveryPaths("/api/admin/health/");
        assertEquals(3, trailingSlash.size());
        assertEquals("/api/admin", trailingSlash.get(0));
        assertEquals("/api", trailingSlash.get(1));
        assertEquals("/", trailingSlash.get(2));

        // Query parameters stripped for API Endpoint Discovery
        List<String> withQuery = PathVariationGenerator_littlespidy.generateEndpointDiscoveryPaths("/api/v1/data?page=1");
        assertEquals(3, withQuery.size());
        assertEquals("/api/v1", withQuery.get(0));
        assertEquals("/api", withQuery.get(1));
        assertEquals("/", withQuery.get(2));
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

    @Test
    public void testEndpointDiscoveryIntruderTabNamingAndParamStripping() {
        java.util.List<String> recordedTabTitles = new java.util.ArrayList<>();
        java.util.List<HttpRequest> recordedRequests = new java.util.ArrayList<>();

        burp.api.montoya.intruder.Intruder mockIntruder = (burp.api.montoya.intruder.Intruder) java.lang.reflect.Proxy.newProxyInstance(
                burp.api.montoya.intruder.Intruder.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.intruder.Intruder.class},
                (proxy, method, args) -> {
                    if ("sendToIntruder".equals(method.getName())) {
                        if (args.length >= 1 && args[0] instanceof HttpRequest req) {
                            recordedRequests.add(req);
                        }
                        if (args.length == 2 && args[1] instanceof String title) {
                            recordedTabTitles.add(title);
                        }
                    }
                    return null;
                }
        );

        burp.api.montoya.MontoyaApi mockApi = (burp.api.montoya.MontoyaApi) java.lang.reflect.Proxy.newProxyInstance(
                burp.api.montoya.MontoyaApi.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.MontoyaApi.class},
                (proxy, method, args) -> {
                    if ("intruder".equals(method.getName())) return mockIntruder;
                    return null;
                }
        );

        com.littlespidy.apiinspector.ui.APIInspectorTab_littlespidy rootTab =
                new com.littlespidy.apiinspector.ui.APIInspectorTab_littlespidy(mockApi);
        com.littlespidy.apiinspector.ui.APIInspectorContextMenu_littlespidy contextMenu =
                new com.littlespidy.apiinspector.ui.APIInspectorContextMenu_littlespidy(mockApi, rootTab);

        HttpRequest original = TestMockHelper_littlespidy.createMockRequest(
                "GET", "https://api.example.com/api/v1/users?token=secret&page=10", "/api/v1/users?token=secret&page=10", Map.of(), ""
        );

        burp.api.montoya.http.message.HttpRequestResponse rr = (burp.api.montoya.http.message.HttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(
                burp.api.montoya.http.message.HttpRequestResponse.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.http.message.HttpRequestResponse.class},
                (proxy, method, args) -> {
                    if ("request".equals(method.getName())) return original;
                    return null;
                }
        );

        burp.api.montoya.ui.contextmenu.ContextMenuEvent event = (burp.api.montoya.ui.contextmenu.ContextMenuEvent) java.lang.reflect.Proxy.newProxyInstance(
                burp.api.montoya.ui.contextmenu.ContextMenuEvent.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.ui.contextmenu.ContextMenuEvent.class},
                (proxy, method, args) -> {
                    if ("selectedRequestResponses".equals(method.getName())) return List.of(rr);
                    if ("messageEditorRequestResponse".equals(method.getName())) return java.util.Optional.empty();
                    return null;
                }
        );

        List<java.awt.Component> menuItems = contextMenu.provideMenuItems(event);
        assertEquals(1, menuItems.size());
        javax.swing.JMenu parentMenu = (javax.swing.JMenu) menuItems.get(0);

        // Find API Endpoint Discovery Intruder Strategy
        javax.swing.JMenuItem discoveryItem = null;
        for (int i = 0; i < parentMenu.getItemCount(); i++) {
            javax.swing.JMenuItem item = parentMenu.getItem(i);
            if (item != null && "API Endpoint Discovery Intruder Strategy".equals(item.getText())) {
                discoveryItem = item;
                break;
            }
        }
        assertNotNull(discoveryItem);

        // Trigger action
        discoveryItem.doClick();

        // Variations for /api/v1/users are: /api/v1, /api, / (3 candidates * 2 = 6 requests)
        assertEquals(6, recordedRequests.size());
        assertEquals(6, recordedTabTitles.size());

        // Verify GET parameters stripped from all requests
        for (HttpRequest req : recordedRequests) {
            assertFalse(req.path().contains("token="), "Query parameter token must be removed");
            assertFalse(req.path().contains("page="), "Query parameter page must be removed");
            assertFalse(req.path().contains("?"), "Question mark must be removed");
        }

        // Verify Tab titles format: Auth/No Auth - Path - Domain
        assertEquals("Auth - /api/v1 - example.com", recordedTabTitles.get(0));
        assertEquals("No Auth - /api/v1 - example.com", recordedTabTitles.get(1));
        assertEquals("Auth - /api - example.com", recordedTabTitles.get(2));
        assertEquals("No Auth - /api - example.com", recordedTabTitles.get(3));
        assertEquals("Auth - / - example.com", recordedTabTitles.get(4));
        assertEquals("No Auth - / - example.com", recordedTabTitles.get(5));
    }
}
