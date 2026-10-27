// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.quickhelper.model.AuthItem_littlespidy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthTokenExtractorServiceTest_littlespidy {

    private AuthTokenExtractorService_littlespidy service;

    @BeforeEach
    void setUp() {
        service = new AuthTokenExtractorService_littlespidy();
    }

    private HttpHeader createMockHeader(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
                HttpHeader.class.getClassLoader(),
                new Class<?>[]{HttpHeader.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "name":
                            return name;
                        case "value":
                            return value;
                        case "toString":
                            return name + ": " + value;
                        default:
                            return null;
                    }
                }
        );
    }

    private HttpRequest createMockRequest(List<HttpHeader> headers) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "headers":
                            return headers;
                        default:
                            return null;
                    }
                }
        );
    }

    @Test
    void testExtractBearerTokenAndAuthHeader() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
        List<HttpHeader> headers = Arrays.asList(
                createMockHeader("Host", "target.local"),
                createMockHeader("Authorization", "Bearer " + token)
        );

        HttpRequest req = createMockRequest(headers);

        assertEquals(token, service.extractBearerToken(req));
        assertEquals("Bearer " + token, service.extractAuthHeader(req));

        List<AuthItem_littlespidy> items = service.extractAll(req);
        assertEquals(2, items.size());

        assertEquals("Bearer Token", items.get(0).getType());
        assertEquals("Bearer (raw token)", items.get(0).getName());
        assertEquals(token, items.get(0).getValue());

        assertEquals("Auth Header", items.get(1).getType());
        assertEquals("Authorization", items.get(1).getName());
        assertEquals("Bearer " + token, items.get(1).getValue());
    }

    @Test
    void testExtractBasicAuthHeaderWithoutBearer() {
        String basicVal = "Basic YWRtaW46c2VjcmV0";
        List<HttpHeader> headers = Collections.singletonList(
                createMockHeader("Authorization", basicVal)
        );

        HttpRequest req = createMockRequest(headers);

        assertNull(service.extractBearerToken(req));
        assertEquals(basicVal, service.extractAuthHeader(req));

        List<AuthItem_littlespidy> items = service.extractAll(req);
        assertEquals(1, items.size());
        assertEquals("Auth Header", items.get(0).getType());
        assertEquals(basicVal, items.get(0).getValue());
    }

    @Test
    void testExtractCookiesHeaderAndIndividualCookies() {
        String cookieStr = "session_id=abc123xyz; csrf_token=def456; theme=dark";
        List<HttpHeader> headers = Collections.singletonList(
                createMockHeader("Cookie", cookieStr)
        );

        HttpRequest req = createMockRequest(headers);

        assertEquals(cookieStr, service.extractCookieHeader(req));

        List<AuthItem_littlespidy> items = service.extractAll(req);
        assertEquals(4, items.size());

        assertEquals("Cookie Header", items.get(0).getType());
        assertEquals(cookieStr, items.get(0).getValue());

        assertEquals("Cookie", items.get(1).getType());
        assertEquals("session_id", items.get(1).getName());
        assertEquals("abc123xyz", items.get(1).getValue());

        assertEquals("Cookie", items.get(2).getType());
        assertEquals("csrf_token", items.get(2).getName());
        assertEquals("def456", items.get(2).getValue());

        assertEquals("Cookie", items.get(3).getType());
        assertEquals("theme", items.get(3).getName());
        assertEquals("dark", items.get(3).getValue());
    }

    @Test
    void testExtractCustomAuthHeaders() {
        List<HttpHeader> headers = Arrays.asList(
                createMockHeader("X-Api-Key", "api-key-99999"),
                createMockHeader("X-Auth-Token", "auth-token-88888")
        );

        HttpRequest req = createMockRequest(headers);

        List<AuthItem_littlespidy> items = service.extractAll(req);
        assertEquals(2, items.size());

        assertEquals("Custom Header", items.get(0).getType());
        assertEquals("X-Api-Key", items.get(0).getName());
        assertEquals("api-key-99999", items.get(0).getValue());

        assertEquals("Custom Header", items.get(1).getType());
        assertEquals("X-Auth-Token", items.get(1).getName());
        assertEquals("auth-token-88888", items.get(1).getValue());
    }

    @Test
    void testEmptyAndNullRequest() {
        assertTrue(service.extractAll(null).isEmpty());
        assertNull(service.extractBearerToken(null));
        assertNull(service.extractAuthHeader(null));
        assertNull(service.extractCookieHeader(null));

        HttpRequest emptyReq = createMockRequest(Collections.emptyList());
        assertTrue(service.extractAll(emptyReq).isEmpty());
        assertNull(service.extractBearerToken(emptyReq));
        assertNull(service.extractAuthHeader(emptyReq));
        assertNull(service.extractCookieHeader(emptyReq));
    }
}
