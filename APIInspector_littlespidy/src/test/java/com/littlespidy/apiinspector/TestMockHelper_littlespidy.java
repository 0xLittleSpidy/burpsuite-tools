// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Test mock helper for Montoya API HttpRequest, HttpResponse, and ByteArray objects.
 */
public class TestMockHelper_littlespidy {

    public static HttpRequest createMockRequest(String method, String url, String path, Map<String, String> initialHeaders, String body) {
        Map<String, String> headers = initialHeaders != null ? new LinkedHashMap<>(initialHeaders) : new LinkedHashMap<>();
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, invokedMethod, args) -> {
                    String mName = invokedMethod.getName();
                    if ("method".equals(mName)) return method != null ? method : "GET";
                    if ("url".equals(mName)) return url != null ? url : "https://example.com" + path;
                    if ("path".equals(mName)) return path;
                    if ("withPath".equals(mName) && args.length == 1) {
                        return createMockRequest(method, url, (String) args[0], new LinkedHashMap<>(headers), body);
                    }
                    if ("headerValue".equals(mName) && args.length == 1) {
                        String target = (String) args[0];
                        for (Map.Entry<String, String> e : headers.entrySet()) {
                            if (e.getKey().equalsIgnoreCase(target)) return e.getValue();
                        }
                        return null;
                    }
                    if ("hasHeader".equals(mName) && args.length == 1) {
                        String target = (String) args[0];
                        for (String k : headers.keySet()) {
                            if (k.equalsIgnoreCase(target)) return true;
                        }
                        return false;
                    }
                    if ("withHeader".equals(mName) && args.length == 2) {
                        Map<String, String> next = new LinkedHashMap<>(headers);
                        next.put((String) args[0], (String) args[1]);
                        return createMockRequest(method, url, path, next, body);
                    }
                    if ("headers".equals(mName)) {
                        java.util.List<burp.api.montoya.http.message.HttpHeader> list = new java.util.ArrayList<>();
                        for (Map.Entry<String, String> e : headers.entrySet()) {
                            list.add(createMockHeader(e.getKey(), e.getValue()));
                        }
                        return list;
                    }
                    if ("withRemovedHeader".equals(mName) && args.length == 1) {
                        String toRemove = (String) args[0];
                        Map<String, String> next = new LinkedHashMap<>();
                        for (Map.Entry<String, String> e : headers.entrySet()) {
                            if (!e.getKey().equalsIgnoreCase(toRemove)) {
                                next.put(e.getKey(), e.getValue());
                            }
                        }
                        return createMockRequest(method, url, path, next, body);
                    }
                    if ("bodyToString".equals(mName)) return body;
                    if ("toByteArray".equals(mName)) {
                        byte[] reqBytes = ((method != null ? method : "GET") + " " + path + " HTTP/1.1\r\n\r\n" + (body != null ? body : "")).getBytes(StandardCharsets.UTF_8);
                        return (ByteArray) Proxy.newProxyInstance(
                                ByteArray.class.getClassLoader(),
                                new Class<?>[]{ByteArray.class},
                                (p, m, a) -> {
                                    if ("length".equals(m.getName())) return reqBytes.length;
                                    if ("getBytes".equals(m.getName())) return reqBytes;
                                    return null;
                                }
                        );
                    }
                    if ("httpService".equals(mName)) {
                        return createMockHttpService("example.com", 443, true);
                    }
                    if ("withService".equals(mName) && args.length == 1) {
                        return proxy;
                    }
                    if ("toString".equals(mName)) {
                        return (method != null ? method : "GET") + " " + path + " HTTP/1.1\r\n";
                    }
                    return null;
                }
        );
    }

    public static HttpService createMockHttpService(String host, int port, boolean secure) {
        return (HttpService) Proxy.newProxyInstance(
                HttpService.class.getClassLoader(),
                new Class<?>[]{HttpService.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("host".equals(name)) return host;
                    if ("port".equals(name)) return port;
                    if ("secure".equals(name)) return secure;
                    return null;
                }
        );
    }

    public static burp.api.montoya.http.message.HttpHeader createMockHeader(String name, String value) {
        return (burp.api.montoya.http.message.HttpHeader) Proxy.newProxyInstance(
                burp.api.montoya.http.message.HttpHeader.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.http.message.HttpHeader.class},
                (proxy, method, args) -> {
                    String mName = method.getName();
                    if ("name".equals(mName)) return name;
                    if ("value".equals(mName)) return value;
                    if ("toString".equals(mName)) return name + ": " + value;
                    return null;
                }
        );
    }

    public static HttpResponse createMockResponse(int statusCode, Map<String, String> headers, String body) {
        byte[] bytes = body != null ? body.getBytes(StandardCharsets.UTF_8) : new byte[0];
        ByteArray mockByteArray = (ByteArray) Proxy.newProxyInstance(
                ByteArray.class.getClassLoader(),
                new Class<?>[]{ByteArray.class},
                (proxy, method, args) -> {
                    if ("length".equals(method.getName())) return bytes.length;
                    if ("getBytes".equals(method.getName())) return bytes;
                    return null;
                }
        );

        return (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(),
                new Class<?>[]{HttpResponse.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("statusCode".equals(name)) return (short) statusCode;
                    if ("body".equals(name)) return mockByteArray;
                    if ("toByteArray".equals(name)) return mockByteArray;
                    if ("bodyToString".equals(name)) return body;
                    if ("headers".equals(name)) {
                        java.util.List<burp.api.montoya.http.message.HttpHeader> list = new java.util.ArrayList<>();
                        if (headers != null) {
                            for (Map.Entry<String, String> e : headers.entrySet()) {
                                list.add(createMockHeader(e.getKey(), e.getValue()));
                            }
                        }
                        return list;
                    }
                    if ("headerValue".equals(name) && args.length == 1) {
                        String target = (String) args[0];
                        if (headers != null) {
                            for (Map.Entry<String, String> e : headers.entrySet()) {
                                if (e.getKey().equalsIgnoreCase(target)) return e.getValue();
                            }
                        }
                        return null;
                    }
                    if ("mimeType".equals(name)) return null;
                    return null;
                }
        );
    }

    public static burp.api.montoya.http.message.HttpRequestResponse createMockHttpRequestResponse(HttpRequest request, HttpResponse response) {
        return (burp.api.montoya.http.message.HttpRequestResponse) Proxy.newProxyInstance(
                burp.api.montoya.http.message.HttpRequestResponse.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.http.message.HttpRequestResponse.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("request".equals(name)) return request;
                    if ("response".equals(name)) return response;
                    if ("hasResponse".equals(name)) return response != null;
                    if ("httpService".equals(name)) return request != null ? request.httpService() : null;
                    return null;
                }
        );
    }
}
