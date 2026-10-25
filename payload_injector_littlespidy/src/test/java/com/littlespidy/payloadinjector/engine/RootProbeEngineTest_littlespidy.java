// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.engine;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Automated test suite for RootProbeEngine_littlespidy verifying:
 * - HTTP PUT file upload probe construction targeting the web root.
 * - HTTP GET robots.txt probe construction targeting the web root.
 * - Preserving auth headers and session cookies when available.
 * - Host header resolution and fallback behavior.
 *
 * @author littlespidy
 */
public class RootProbeEngineTest_littlespidy {

    @BeforeAll
    static void setUpMontoyaFactory() {
        if (burp.api.montoya.internal.ObjectFactoryLocator.FACTORY == null) {
            burp.api.montoya.internal.ObjectFactoryLocator.FACTORY = (burp.api.montoya.internal.MontoyaObjectFactory) Proxy.newProxyInstance(
                    RootProbeEngineTest_littlespidy.class.getClassLoader(),
                    new Class<?>[]{burp.api.montoya.internal.MontoyaObjectFactory.class},
                    (proxy, method, args) -> {
                        String methodName = method.getName();
                        if ("httpRequest".equals(methodName)) {
                            if (args.length == 1) {
                                if (args[0] instanceof ByteArray ba) {
                                    return createMockHttpRequest(new String(ba.getBytes(), StandardCharsets.UTF_8), null);
                                }
                                if (args[0] instanceof String s) {
                                    return createMockHttpRequest(s, null);
                                }
                            }
                            if (args.length == 2) {
                                HttpService svc = (HttpService) args[0];
                                if (args[1] instanceof ByteArray ba) {
                                    return createMockHttpRequest(new String(ba.getBytes(), StandardCharsets.UTF_8), svc);
                                }
                                if (args[1] instanceof String s) {
                                    return createMockHttpRequest(s, svc);
                                }
                            }
                        }
                        if ("byteArray".equals(methodName)) {
                            if (args != null && args.length > 0) {
                                if (args[0] instanceof byte[] b) return createMockByteArray(b);
                                if (args[0] instanceof String s) return createMockByteArray(s.getBytes(StandardCharsets.UTF_8));
                            }
                            return createMockByteArray(new byte[0]);
                        }
                        return null;
                    }
            );
        }
    }

    private static HttpRequest createMockHttpRequest(String raw, HttpService service) {
        return (HttpRequest) Proxy.newProxyInstance(
                RootProbeEngineTest_littlespidy.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("equals".equals(name)) return proxy == args[0];
                    if ("hashCode".equals(name)) return System.identityHashCode(proxy);
                    if ("toString".equals(name)) return raw;
                    if ("httpService".equals(name)) return service;
                    if ("toByteArray".equals(name)) return createMockByteArray(raw.getBytes(StandardCharsets.UTF_8));
                    if ("headerValue".equals(name) && args != null && args.length > 0) {
                        String headerName = (String) args[0];
                        String lower = raw.toLowerCase();
                        String search = "\n" + headerName.toLowerCase() + ":";
                        int idx = lower.indexOf(search);
                        if (idx == -1 && lower.startsWith(headerName.toLowerCase() + ":")) {
                            idx = 0;
                        } else if (idx != -1) {
                            idx += 1;
                        }
                        if (idx != -1) {
                            int colon = raw.indexOf(':', idx);
                            int lineEnd = raw.indexOf("\r\n", colon);
                            if (lineEnd == -1) lineEnd = raw.indexOf('\n', colon);
                            if (lineEnd == -1) lineEnd = raw.length();
                            return raw.substring(colon + 1, lineEnd).trim();
                        }
                        return null;
                    }
                    return null;
                }
        );
    }

    private static ByteArray createMockByteArray(byte[] bytes) {
        return (ByteArray) Proxy.newProxyInstance(
                RootProbeEngineTest_littlespidy.class.getClassLoader(),
                new Class<?>[]{ByteArray.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("equals".equals(name)) return proxy == args[0];
                    if ("hashCode".equals(name)) return System.identityHashCode(proxy);
                    if ("getBytes".equals(name)) return bytes;
                    if ("length".equals(name)) return bytes.length;
                    if ("toString".equals(name)) return new String(bytes, StandardCharsets.UTF_8);
                    return null;
                }
        );
    }

    private static HttpService createMockHttpService(String host, int port, boolean secure) {
        return (HttpService) Proxy.newProxyInstance(
                RootProbeEngineTest_littlespidy.class.getClassLoader(),
                new Class<?>[]{HttpService.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("equals".equals(name)) return proxy == args[0];
                    if ("hashCode".equals(name)) return System.identityHashCode(proxy);
                    if ("host".equals(name)) return host;
                    if ("port".equals(name)) return port;
                    if ("secure".equals(name)) return secure;
                    return null;
                }
        );
    }

    @Test
    void testBuildPutUploadRequestDefault() {
        HttpService service = createMockHttpService("example.com", 443, true);
        String raw = "GET /api/v1/users?id=123 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 Custom\r\nCookie: session=abc123xyz\r\n\r\n";
        HttpRequest base = createMockHttpRequest(raw, service);

        HttpRequest putReq = RootProbeEngine_littlespidy.buildPutUploadRequest(base);
        assertNotNull(putReq);

        String reqStr = putReq.toString();
        assertTrue(reqStr.startsWith("PUT " + RootProbeEngine_littlespidy.DEFAULT_PUT_FILENAME + " HTTP/1.1\r\n"));
        assertTrue(reqStr.contains("Host: example.com\r\n"));
        assertTrue(reqStr.contains("User-Agent: Mozilla/5.0 Custom\r\n"));
        assertTrue(reqStr.contains("Cookie: session=abc123xyz\r\n"));
        assertTrue(reqStr.contains("Content-Type: text/plain\r\n"));
        assertTrue(reqStr.contains("Content-Length: "));
        assertTrue(reqStr.contains("Connection: close\r\n"));
        assertTrue(reqStr.contains(RootProbeEngine_littlespidy.DEFAULT_PUT_BODY));
        assertEquals(service, putReq.httpService());
    }

    @Test
    void testBuildPutUploadRequestCustomFileAndBody() {
        HttpService service = createMockHttpService("test.local", 8080, false);
        String raw = "POST /submit HTTP/1.1\r\nHost: test.local:8080\r\nAuthorization: Bearer mytoken\r\n\r\n{\"key\":\"val\"}";
        HttpRequest base = createMockHttpRequest(raw, service);

        HttpRequest putReq = RootProbeEngine_littlespidy.buildPutUploadRequest(base, "custom_upload.txt", "Test file data\n");
        assertNotNull(putReq);

        String reqStr = putReq.toString();
        assertTrue(reqStr.startsWith("PUT /custom_upload.txt HTTP/1.1\r\n"));
        assertTrue(reqStr.contains("Host: test.local:8080\r\n"));
        assertTrue(reqStr.contains("Authorization: Bearer mytoken\r\n"));
        assertTrue(reqStr.contains("Test file data\n"));
    }

    @Test
    void testBuildRobotsTxtRequest() {
        HttpService service = createMockHttpService("target.org", 443, true);
        String raw = "GET /catalog/products/item?id=99 HTTP/1.1\r\nHost: target.org\r\nUser-Agent: BurpTest/1.0\r\nCookie: id=777\r\n\r\n";
        HttpRequest base = createMockHttpRequest(raw, service);

        HttpRequest robotsReq = RootProbeEngine_littlespidy.buildRobotsTxtRequest(base);
        assertNotNull(robotsReq);

        String reqStr = robotsReq.toString();
        assertTrue(reqStr.startsWith("GET /robots.txt HTTP/1.1\r\n"));
        assertTrue(reqStr.contains("Host: target.org\r\n"));
        assertTrue(reqStr.contains("User-Agent: BurpTest/1.0\r\n"));
        assertTrue(reqStr.contains("Cookie: id=777\r\n"));
        assertTrue(reqStr.contains("Accept: text/plain, */*\r\n"));
        assertTrue(reqStr.contains("Connection: close\r\n"));
        assertEquals(service, robotsReq.httpService());
    }

    @Test
    void testBuildWebRootProbeRequestEdgeCases() {
        assertNull(RootProbeEngine_littlespidy.buildPutUploadRequest(null));
        assertNull(RootProbeEngine_littlespidy.buildRobotsTxtRequest(null));
        assertNull(RootProbeEngine_littlespidy.buildWebRootProbeRequest(null, "/robots.txt"));

        HttpService service = createMockHttpService("fallback.internal", 80, false);
        HttpRequest baseWithoutHost = createMockHttpRequest("GET / HTTP/1.1\r\n\r\n", service);

        HttpRequest probe = RootProbeEngine_littlespidy.buildWebRootProbeRequest(baseWithoutHost, "test_dir");
        assertNotNull(probe);
        assertTrue(probe.toString().startsWith("GET /test_dir HTTP/1.1\r\n"));
        assertTrue(probe.toString().contains("Host: fallback.internal\r\n"));
    }
}
