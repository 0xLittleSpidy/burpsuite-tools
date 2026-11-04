// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ProxyAuthHistoryServiceTest_littlespidy {

    private HttpRequest createMockRequest(Map<String, String> headerMap) {
        Map<String, String> map = new HashMap<>(headerMap);
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("hasHeader".equals(name) && args.length == 1 && args[0] instanceof String) {
                        return map.containsKey(((String) args[0]).toLowerCase());
                    } else if ("headerValue".equals(name) && args.length == 1 && args[0] instanceof String) {
                        return map.get(((String) args[0]).toLowerCase());
                    } else if ("withUpdatedHeader".equals(name) && args.length == 2) {
                        Map<String, String> next = new HashMap<>(map);
                        next.put(((String) args[0]).toLowerCase(), (String) args[1]);
                        return createMockRequest(next);
                    } else if ("withAddedHeader".equals(name) && args.length == 2) {
                        Map<String, String> next = new HashMap<>(map);
                        next.put(((String) args[0]).toLowerCase(), (String) args[1]);
                        return createMockRequest(next);
                    }
                    return null;
                }
        );
    }

    @Test
    public void testReplaceJwtInRequestWithoutPriorAuth() {
        ProxyAuthHistoryService_littlespidy service = new ProxyAuthHistoryService_littlespidy(null);
        Map<String, String> headers = new HashMap<>();
        headers.put("host", "example.com");
        HttpRequest req = createMockRequest(headers);

        String newJwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.mockSignature";
        HttpRequest updated = service.replaceJwt(req, newJwt);

        assertNotNull(updated);
        assertTrue(updated.hasHeader("Authorization"));
        assertEquals(newJwt, updated.headerValue("Authorization"));
    }

    @Test
    public void testReplaceJwtInRequestWithExistingAuth() {
        ProxyAuthHistoryService_littlespidy service = new ProxyAuthHistoryService_littlespidy(null);
        Map<String, String> headers = new HashMap<>();
        headers.put("host", "example.com");
        headers.put("authorization", "Bearer old_token");
        HttpRequest req = createMockRequest(headers);

        String newJwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuZXdVc2VyIn0.mockSignature";
        HttpRequest updated = service.replaceJwt(req, newJwt);

        assertNotNull(updated);
        assertEquals(newJwt, updated.headerValue("Authorization"));
    }

    @Test
    public void testReplaceCookieInRequestWithoutPriorCookie() {
        ProxyAuthHistoryService_littlespidy service = new ProxyAuthHistoryService_littlespidy(null);
        Map<String, String> headers = new HashMap<>();
        headers.put("host", "example.com");
        HttpRequest req = createMockRequest(headers);

        String newCookie = "session=user_session_12345; auth_id=98765";
        HttpRequest updated = service.replaceCookie(req, newCookie);

        assertNotNull(updated);
        assertTrue(updated.hasHeader("Cookie"));
        assertEquals(newCookie, updated.headerValue("Cookie"));
    }

    @Test
    public void testReplaceCookieInRequestWithExistingCookie() {
        ProxyAuthHistoryService_littlespidy service = new ProxyAuthHistoryService_littlespidy(null);
        Map<String, String> headers = new HashMap<>();
        headers.put("host", "example.com");
        headers.put("cookie", "session=old_session");
        HttpRequest req = createMockRequest(headers);

        String newCookie = "session=new_session_999";
        HttpRequest updated = service.replaceCookie(req, newCookie);

        assertNotNull(updated);
        assertEquals(newCookie, updated.headerValue("Cookie"));
    }
}
