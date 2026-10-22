// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.scope.ScopeChangeHandler;
import com.littlespidy.quickhelper.model.ExtractionOptions_littlespidy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DomainExtractorServiceTest_littlespidy {

    private DomainExtractorService_littlespidy service;

    @BeforeEach
    void setUp() {
        service = new DomainExtractorService_littlespidy(null, new ClipboardService_littlespidy());
    }

    private HttpRequestResponse createMockItem(String host, int port, boolean secure, String path) {
        HttpService httpService = (HttpService) Proxy.newProxyInstance(
                HttpService.class.getClassLoader(),
                new Class<?>[]{HttpService.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "host":
                            return host;
                        case "port":
                            return port;
                        case "secure":
                            return secure;
                        case "toString":
                            return (secure ? "https" : "http") + "://" + host + ":" + port;
                        default:
                            return null;
                    }
                }
        );

        HttpRequest request = (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "httpService":
                            return httpService;
                        case "url":
                            boolean defaultPort = (secure && port == 443) || (!secure && port == 80);
                            String portSuffix = defaultPort ? "" : ":" + port;
                            return (secure ? "https" : "http") + "://" + host + portSuffix + path;
                        default:
                            return null;
                    }
                }
        );

        return (HttpRequestResponse) Proxy.newProxyInstance(
                HttpRequestResponse.class.getClassLoader(),
                new Class<?>[]{HttpRequestResponse.class},
                (proxy, method, args) -> {
                    if ("request".equals(method.getName())) {
                        return request;
                    }
                    if ("httpService".equals(method.getName())) {
                        return httpService;
                    }
                    return null;
                }
        );
    }

    @Test
    void testExtractAllDomainsUniqueAndSorted() {
        List<HttpRequestResponse> items = Arrays.asList(
                createMockItem("example.com", 443, true, "/"),
                createMockItem("EXAMPLE.COM", 443, true, "/about"),
                createMockItem("api.example.com", 443, true, "/v1"),
                createMockItem("sub.test.org", 80, false, "/"),
                createMockItem("alpha.internal", 8080, false, "/")
        );

        List<String> domains = service.extractDomains(items, null, ExtractionOptions_littlespidy.allDomains());

        assertEquals(4, domains.size());
        assertEquals("alpha.internal", domains.get(0));
        assertEquals("api.example.com", domains.get(1));
        assertEquals("example.com", domains.get(2));
        assertEquals("sub.test.org", domains.get(3));
    }

    @Test
    void testExtractAllDomainsWithSchema() {
        List<HttpRequestResponse> items = Arrays.asList(
                createMockItem("example.com", 443, true, "/"),
                createMockItem("example.com", 80, false, "/"),
                createMockItem("api.test.org", 8080, false, "/"),
                createMockItem("secure.test.org", 8443, true, "/")
        );

        List<String> results = service.extractDomains(items, null, ExtractionOptions_littlespidy.allDomainsWithSchema());

        assertEquals(4, results.size());
        assertEquals("http://api.test.org:8080", results.get(0));
        assertEquals("http://example.com", results.get(1));
        assertEquals("https://example.com", results.get(2));
        assertEquals("https://secure.test.org:8443", results.get(3));
    }

    @Test
    void testInScopeFiltering() {
        List<HttpRequestResponse> items = Arrays.asList(
                createMockItem("target.com", 443, true, "/api"),
                createMockItem("out-of-scope.net", 443, true, "/login")
        );

        Scope testScope = new Scope() {
            @Override
            public boolean isInScope(String url) {
                return url != null && url.contains("target.com");
            }

            @Override
            public void includeInScope(String url) {}

            @Override
            public void excludeFromScope(String url) {}

            @Override
            public Registration registerScopeChangeHandler(ScopeChangeHandler handler) {
                return null;
            }
        };

        List<String> inScopeDomains = service.extractDomains(items, testScope, ExtractionOptions_littlespidy.inScopeDomains());
        assertEquals(1, inScopeDomains.size());
        assertEquals("target.com", inScopeDomains.get(0));

        List<String> inScopeWithSchema = service.extractDomains(items, testScope, ExtractionOptions_littlespidy.inScopeDomainsWithSchema());
        assertEquals(1, inScopeWithSchema.size());
        assertEquals("https://target.com", inScopeWithSchema.get(0));
    }

    @Test
    void testEmptyAndNullHandling() {
        assertTrue(service.extractDomains(null, null, ExtractionOptions_littlespidy.allDomains()).isEmpty());
        assertTrue(service.extractDomains(Collections.emptyList(), null, ExtractionOptions_littlespidy.allDomains()).isEmpty());

        List<HttpRequestResponse> itemsWithNulls = new ArrayList<>();
        itemsWithNulls.add(null);
        itemsWithNulls.add(createMockItem("valid.org", 80, false, "/"));
        List<String> results = service.extractDomains(itemsWithNulls, null, ExtractionOptions_littlespidy.allDomains());
        assertEquals(1, results.size());
        assertEquals("valid.org", results.get(0));
    }
}
