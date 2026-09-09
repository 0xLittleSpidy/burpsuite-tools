// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.jwtcomparator.attacker.engine.JwtAttackEngine;
import com.littlespidy.jwtcomparator.attacker.model.AttackedRequestEntry;
import com.littlespidy.jwtcomparator.attacker.model.JwtTokenInjector;
import com.littlespidy.jwtcomparator.attacker.model.TokenAttackResult;
import com.littlespidy.jwtcomparator.attacker.ui.TokenAttackTableModel;
import com.littlespidy.jwtcomparator.attacker.ui.TokenAttackerPanel;
import com.littlespidy.jwtcomparator.model.JWTTokenModel;
import com.littlespidy.jwtcomparator.ui.JWTComparatorTab;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class TokenAttackerTest {

    private static String createTestJwt(String headerJson, String payloadJson) {
        String encHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String encPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return encHeader + "." + encPayload + ".dummy_signature_xyz";
    }

    @BeforeAll
    public static void setupHeadless() {
        System.setProperty("java.awt.headless", "true");
    }

    private static HttpHeader mockHeader(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
                HttpHeader.class.getClassLoader(),
                new Class<?>[]{HttpHeader.class},
                (proxy, method, args) -> {
                    if ("name".equals(method.getName())) return name;
                    if ("value".equals(method.getName())) return value;
                    return null;
                }
        );
    }

    private static HttpRequest mockRequest(String method, String url, String path, Map<String, String> initialHeaders) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (initialHeaders != null) {
            for (Map.Entry<String, String> e : initialHeaders.entrySet()) {
                headers.put(e.getKey(), e.getValue());
            }
        }

        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, invokedMethod, args) -> {
                    String name = invokedMethod.getName();
                    switch (name) {
                        case "method":
                            return method;
                        case "url":
                            return url;
                        case "path":
                            return path;
                        case "hasHeader":
                            String targetName = args[0] instanceof HttpHeader ?
                                    ((HttpHeader) args[0]).name() : (String) args[0];
                            return headers.keySet().stream().anyMatch(k -> k.equalsIgnoreCase(targetName));
                        case "headerValue":
                            String searchName = (String) args[0];
                            for (Map.Entry<String, String> entry : headers.entrySet()) {
                                if (entry.getKey().equalsIgnoreCase(searchName)) {
                                    return entry.getValue();
                                }
                            }
                            return null;
                        case "headers":
                            List<HttpHeader> list = new ArrayList<>();
                            for (Map.Entry<String, String> e : headers.entrySet()) {
                                list.add(mockHeader(e.getKey(), e.getValue()));
                            }
                            return list;
                        case "withUpdatedHeader": {
                            String hName = (String) args[0];
                            String hVal = (String) args[1];
                            Map<String, String> copy = new LinkedHashMap<>();
                            boolean found = false;
                            for (Map.Entry<String, String> e : headers.entrySet()) {
                                if (e.getKey().equalsIgnoreCase(hName)) {
                                    copy.put(e.getKey(), hVal);
                                    found = true;
                                } else {
                                    copy.put(e.getKey(), e.getValue());
                                }
                            }
                            if (!found) {
                                copy.put(hName, hVal);
                            }
                            return mockRequest(method, url, path, copy);
                        }
                        case "withAddedHeader": {
                            String hName = (String) args[0];
                            String hVal = (String) args[1];
                            Map<String, String> copy = new LinkedHashMap<>(headers);
                            copy.put(hName, hVal);
                            return mockRequest(method, url, path, copy);
                        }
                        case "withRemovedHeader": {
                            String hName = (String) args[0];
                            Map<String, String> copy = new LinkedHashMap<>();
                            for (Map.Entry<String, String> e : headers.entrySet()) {
                                if (!e.getKey().equalsIgnoreCase(hName)) {
                                    copy.put(e.getKey(), e.getValue());
                                }
                            }
                            return mockRequest(method, url, path, copy);
                        }
                        case "toString":
                            return method + " " + path + " HTTP/1.1\r\n" + headers;
                        default:
                            return null;
                    }
                }
        );
    }

    private static HttpResponse mockResponse(int statusCode, String reason, int bodyLength) {
        return (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(),
                new Class<?>[]{HttpResponse.class},
                (proxy, invokedMethod, args) -> {
                    String name = invokedMethod.getName();
                    switch (name) {
                        case "statusCode":
                            return (short) statusCode;
                        case "reasonPhrase":
                            return reason;
                        case "body":
                            return (burp.api.montoya.core.ByteArray) Proxy.newProxyInstance(
                                    burp.api.montoya.core.ByteArray.class.getClassLoader(),
                                    new Class<?>[]{burp.api.montoya.core.ByteArray.class},
                                    (bProxy, bMethod, bArgs) -> {
                                        if ("length".equals(bMethod.getName())) return bodyLength;
                                        return null;
                                    }
                            );
                        default:
                            return null;
                    }
                }
        );
    }

    @Test
    public void testTokenInjectorAuthorizationHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Host", "example.com");
        headers.put("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig1");

        HttpRequest original = mockRequest("GET", "https://example.com/api/v1/users", "/api/v1/users", headers);

        String newToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI5OTkiLCJyb2xlIjoiYWRtaW4ifQ.newsig";
        HttpRequest mutated = JwtTokenInjector.injectToken(original, newToken);

        assertNotNull(mutated);
        assertTrue(mutated.hasHeader("Authorization"));
        assertEquals("Bearer " + newToken, mutated.headerValue("Authorization"));
    }

    @Test
    public void testTokenInjectorCookiesAndCustomHeaders() {
        String oldJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig1";
        Map<String, String> headers = new HashMap<>();
        headers.put("Host", "example.com");
        headers.put("Cookie", "session_id=abc12345; auth_token=" + oldJwt + "; theme=dark");
        headers.put("x-access-token", oldJwt);

        HttpRequest original = mockRequest("POST", "https://example.com/api/v1/action", "/api/v1/action", headers);

        String newJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI3NzcifQ.sig2";
        HttpRequest mutated = JwtTokenInjector.injectToken(original, newJwt);

        assertNotNull(mutated);
        assertEquals(newJwt, mutated.headerValue("x-access-token"));

        String cookieVal = mutated.headerValue("Cookie");
        assertNotNull(cookieVal);
        assertTrue(cookieVal.contains("auth_token=" + newJwt));
        assertTrue(cookieVal.contains("session_id=abc12345"));
        assertTrue(cookieVal.contains("theme=dark"));
    }

    @Test
    public void testTokenInjectorFallbackAuthorizationHeader() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Host", "example.com");

        HttpRequest original = mockRequest("GET", "https://example.com/public/info", "/public/info", headers);

        String newJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDAifQ.sig";
        HttpRequest mutated = JwtTokenInjector.injectToken(original, newJwt);

        assertNotNull(mutated);
        assertTrue(mutated.hasHeader("Authorization"));
        assertEquals("Bearer " + newJwt, mutated.headerValue("Authorization"));
    }

    @Test
    public void testTokenInjectorStripAuth() {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig1";
        Map<String, String> headers = new HashMap<>();
        headers.put("Host", "example.com");
        headers.put("Authorization", "Bearer " + jwt);
        headers.put("x-auth-token", jwt);
        headers.put("Cookie", "jwt=" + jwt + "; theme=dark");

        HttpRequest original = mockRequest("GET", "https://example.com/api/secret", "/api/secret", headers);

        HttpRequest stripped = JwtTokenInjector.stripAuth(original);
        assertNotNull(stripped);
        assertFalse(stripped.hasHeader("Authorization"));
        assertFalse(stripped.hasHeader("x-auth-token"));

        String cookieVal = stripped.headerValue("Cookie");
        assertNotNull(cookieVal);
        assertFalse(cookieVal.contains("jwt="));
        assertTrue(cookieVal.contains("theme=dark"));
    }

    @Test
    public void testTokenAttackResultStatusClassification() {
        HttpRequest req = mockRequest("GET", "https://example.com/", "/", Map.of());
        HttpResponse resp200 = mockResponse(200, "OK", 10);
        TokenAttackResult r200 = new TokenAttackResult(1, "Admin", 200, "OK", 10, 45, req, resp200, null);
        assertEquals(TokenAttackResult.StatusType.ACCEPTED, r200.getStatusType());
        assertTrue(r200.isAccepted());
        assertFalse(r200.isRejected());

        HttpResponse resp403 = mockResponse(403, "Forbidden", 0);
        TokenAttackResult r403 = new TokenAttackResult(2, "User", 403, "Forbidden", 0, 30, req, resp403, null);
        assertEquals(TokenAttackResult.StatusType.REJECTED, r403.getStatusType());
        assertTrue(r403.isRejected());

        HttpResponse resp302 = mockResponse(302, "Found", 0);
        TokenAttackResult r302 = new TokenAttackResult(3, "Guest", 302, "Found", 0, 20, req, resp302, null);
        assertEquals(TokenAttackResult.StatusType.REDIRECT, r302.getStatusType());

        HttpResponse resp500 = mockResponse(500, "Internal Server Error", 0);
        TokenAttackResult r500 = new TokenAttackResult(4, "Test", 500, "Internal Server Error", 0, 50, req, resp500, null);
        assertEquals(TokenAttackResult.StatusType.SERVER_ERROR, r500.getStatusType());

        TokenAttackResult rFail = TokenAttackResult.failed(5, "Offline", req, "Connection timed out");
        assertEquals(TokenAttackResult.StatusType.FAILED, rFail.getStatusType());
        assertTrue(rFail.getDisplayText().contains("Failed"));
    }

    @Test
    public void testAssessmentBolaDetection() {
        HttpRequest req = mockRequest("GET", "https://example.com/api/admin/users", "/api/admin/users", Map.of());
        HttpResponse resp = mockResponse(200, "OK", 500);
        AttackedRequestEntry entry = new AttackedRequestEntry(1, req, resp);

        JWTTokenModel admin = new JWTTokenModel(1, "Admin");
        JWTTokenModel user = new JWTTokenModel(2, "User");

        // Both Admin and User receive 200 OK -> BOLA / Access Bypass!
        entry.addTokenResult(1, new TokenAttackResult(1, "Admin", 200, "OK", 500, 30, req, resp, null));
        entry.addTokenResult(2, new TokenAttackResult(2, "User", 200, "OK", 500, 28, req, resp, null));

        String assessment = JwtAttackEngine.evaluateAssessment(entry, List.of(admin, user), false);
        assertNotNull(assessment);
        assertTrue(assessment.contains("🚨") && assessment.contains("BOLA"));
    }

    @Test
    public void testAssessmentRoleDifferentiatedEnforced() {
        HttpRequest req = mockRequest("GET", "https://example.com/api/admin/users", "/api/admin/users", Map.of());
        HttpResponse resp200 = mockResponse(200, "OK", 500);
        HttpResponse resp403 = mockResponse(403, "Forbidden", 0);
        AttackedRequestEntry entry = new AttackedRequestEntry(1, req, resp200);

        JWTTokenModel admin = new JWTTokenModel(1, "Admin");
        JWTTokenModel user = new JWTTokenModel(2, "User");

        // Admin 200 OK, User 403 Forbidden -> Properly Enforced
        entry.addTokenResult(1, new TokenAttackResult(1, "Admin", 200, "OK", 500, 30, req, resp200, null));
        entry.addTokenResult(2, new TokenAttackResult(2, "User", 403, "Forbidden", 0, 25, req, resp403, null));

        String assessment = JwtAttackEngine.evaluateAssessment(entry, List.of(admin, user), false);
        assertNotNull(assessment);
        assertTrue(assessment.contains("✔") && assessment.contains("Enforced"));
    }

    @Test
    public void testAssessmentUnauthenticatedAllowed() {
        HttpRequest req = mockRequest("GET", "https://example.com/api/metrics", "/api/metrics", Map.of());
        HttpResponse resp200 = mockResponse(200, "OK", 100);
        AttackedRequestEntry entry = new AttackedRequestEntry(1, req, resp200);

        JWTTokenModel admin = new JWTTokenModel(1, "Admin");
        entry.addTokenResult(1, new TokenAttackResult(1, "Admin", 200, "OK", 100, 20, req, resp200, null));

        // Unauth probe also returned 200 OK -> Flagged as Unauthenticated Access!
        entry.setUnauthenticatedResult(new TokenAttackResult(0, "Unauthenticated", 200, "OK", 100, 15, req, resp200, null));

        String assessment = JwtAttackEngine.evaluateAssessment(entry, List.of(admin), true);
        assertNotNull(assessment);
        assertTrue(assessment.contains("⚠️") && assessment.contains("Unauthenticated Access"));
    }

    @Test
    public void testTokenAttackTableModelDynamicColumns() {
        TokenAttackTableModel model = new TokenAttackTableModel();

        String jwt1 = createTestJwt("{\"alg\":\"HS256\"}", "{\"sub\":\"admin\"}");
        String jwt2 = createTestJwt("{\"alg\":\"HS256\"}", "{\"sub\":\"user\"}");

        JWTTokenModel t1 = new JWTTokenModel(1, "Admin");
        t1.setRawToken(jwt1);
        JWTTokenModel t2 = new JWTTokenModel(2, "Customer");
        t2.setRawToken(jwt2);

        model.updateSchema(List.of(t1, t2), true);

        // Columns: # (0), Method (1), Endpoint/Path (2), Baseline (Orig) (3),
        // T1 (Admin) (4), T2 (Customer) (5), Unauth (6), Assessment (7)
        assertEquals(8, model.getColumnCount());
        assertEquals("#", model.getColumnName(0));
        assertEquals("Method", model.getColumnName(1));
        assertEquals("Endpoint / Path", model.getColumnName(2));
        assertEquals("Baseline (Orig)", model.getColumnName(3));
        assertTrue(model.getColumnName(4).contains("T1"));
        assertTrue(model.getColumnName(4).contains("Admin"));
        assertTrue(model.getColumnName(5).contains("T2"));
        assertTrue(model.getColumnName(5).contains("Customer"));
        assertEquals("Unauth (No Token)", model.getColumnName(6));
        assertEquals("Assessment", model.getColumnName(7));

        // Add entry
        HttpRequest req = mockRequest("GET", "https://example.com/api/v1/orders", "/api/v1/orders", Map.of());
        HttpResponse resp = mockResponse(200, "OK", 300);
        AttackedRequestEntry entry = new AttackedRequestEntry(1, req, resp);
        entry.addTokenResult(1, new TokenAttackResult(1, "Admin", 200, "OK", 300, 15, req, resp, null));
        entry.addTokenResult(2, new TokenAttackResult(2, "Customer", 200, "OK", 300, 18, req, resp, null));
        entry.setAssessment("🚨 BOLA / Access Bypass");

        model.addRequest(entry);
        assertEquals(1, model.getRowCount());

        // Test filtering
        model.applyFilter("Vulnerabilities / Bypasses Only", "");
        assertEquals(1, model.getRowCount());

        model.applyFilter("All Requests", "non-existent-keyword");
        assertEquals(0, model.getRowCount());

        model.applyFilter("All Requests", "orders");
        assertEquals(1, model.getRowCount());
    }

    @Test
    public void testTabOrderingAndAttackerTabIntegration() {
        JWTComparatorTab rootTab = new JWTComparatorTab(null);
        assertNotNull(rootTab.getAttackerPanel());

        javax.swing.JTabbedPane pane = (javax.swing.JTabbedPane) rootTab.getComponent(0);
        assertEquals(3, pane.getTabCount());
        assertEquals("Welcome & Guide", pane.getTitleAt(0));
        assertEquals("JWT Comparator", pane.getTitleAt(1));
        assertEquals("Token Attacker", pane.getTitleAt(2));

        // Test tab selection switching
        rootTab.selectAttackerTab();
        assertEquals(2, pane.getSelectedIndex());

        rootTab.selectComparatorTab();
        assertEquals(1, pane.getSelectedIndex());

        rootTab.selectWelcomeTab();
        assertEquals(0, pane.getSelectedIndex());

        TokenAttackerPanel attackerPanel = rootTab.getAttackerPanel();
        assertNotNull(attackerPanel.getTableModel());
        assertNotNull(attackerPanel.generateTsvContent());
    }
}
