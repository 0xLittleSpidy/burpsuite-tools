// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.engine.ScannerUtils;
import com.littlespidy.responseinspector.model.FindingCategory;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.*;

public class StreamingScanEngineTest_littlespidy {

    private HttpRequestResponse createMockItem(String url, String respBody) {
        HttpRequest req = (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> {
                    if ("url".equals(method.getName())) return url;
                    if ("method".equals(method.getName())) return "GET";
                    if ("headerValue".equals(method.getName())) return "application/json";
                    if ("bodyToString".equals(method.getName())) return "";
                    return null;
                }
        );

        HttpResponse resp = (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(),
                new Class<?>[]{HttpResponse.class},
                (proxy, method, args) -> {
                    if ("bodyToString".equals(method.getName())) return respBody;
                    if ("body".equals(method.getName())) {
                        byte[] bytes = respBody != null ? respBody.getBytes() : new byte[0];
                        return Proxy.newProxyInstance(
                                ByteArray.class.getClassLoader(),
                                new Class<?>[]{ByteArray.class},
                                (bp, bm, ba) -> {
                                    if ("length".equals(bm.getName())) return bytes.length;
                                    if ("getBytes".equals(bm.getName())) return bytes;
                                    return null;
                                }
                        );
                    }
                    if ("headerValue".equals(method.getName())) return "application/json";
                    if ("statusCode".equals(method.getName())) return (short) 200;
                    return null;
                }
        );

        return (HttpRequestResponse) Proxy.newProxyInstance(
                HttpRequestResponse.class.getClassLoader(),
                new Class<?>[]{HttpRequestResponse.class},
                (proxy, method, args) -> {
                    if ("request".equals(method.getName())) return req;
                    if ("response".equals(method.getName())) return resp;
                    if ("hasResponse".equals(method.getName())) return true;
                    return null;
                }
        );
    }

    @Test
    public void testHighVolumeStreamingWithoutMemoryExhaustion() {
        ResponseScanEngine engine = new ResponseScanEngine();

        int totalSimulated = 5000;
        int expectedFindings = 0;

        for (int i = 0; i < totalSimulated; i++) {
            String body;
            if (i % 250 == 0) {
                // Sensitive secret finding
                body = "{\"status\":\"ok\", \"aws_key\":\"AKIA1234567890ABCDEF\"}";
                expectedFindings++;
            } else {
                // Benign traffic with no sensitive data
                body = "{\"count\":" + i + ", \"result\":\"success\"}";
            }

            HttpRequestResponse item = createMockItem("https://example.com/api/" + i, body);
            engine.scanItem(item);
        }

        assertTrue(engine.getTotalFindingsCount() >= expectedFindings);
        assertTrue(engine.getDataStore(FindingCategory.SECRET).size() >= expectedFindings);
        assertTrue(engine.getDataStore(FindingCategory.SECRET).size() <= expectedFindings * 3);
    }

    @Test
    public void testRepeaterTrafficIsBounded() {
        ResponseScanEngine engine = new ResponseScanEngine();

        for (int i = 0; i < 600; i++) {
            HttpRequestResponse item = createMockItem("https://example.com/repeater/" + i, "{\"data\": " + i + "}");
            engine.addRepeaterItem(item);
        }

        assertEquals(500, engine.getRepeaterTrafficCount());
    }

    @Test
    public void testOversizedResponseThreshold() {
        assertEquals(5 * 1024 * 1024, ScannerUtils.MAX_RESPONSE_SIZE);
    }
}
