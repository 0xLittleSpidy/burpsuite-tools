// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.engine.ParameterScanner_littlespidy;
import com.littlespidy.responseinspector.model.ParameterEntry_littlespidy;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ParameterScannerTest_littlespidy {

    private HttpRequestResponse createMockItem(
            String reqBody,
            String reqContentType,
            String respBody,
            String respContentType
    ) {
        HttpRequest req = (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> {
                    if ("bodyToString".equals(method.getName())) return reqBody;
                    if ("headerValue".equals(method.getName())) {
                        if (args != null && args.length > 0 && "Content-Type".equalsIgnoreCase((String) args[0])) {
                            return reqContentType;
                        }
                    }
                    if ("url".equals(method.getName())) return "https://example.com/api";
                    if ("method".equals(method.getName())) return "POST";
                    return null;
                }
        );

        HttpResponse resp = (HttpResponse) Proxy.newProxyInstance(
                HttpResponse.class.getClassLoader(),
                new Class<?>[]{HttpResponse.class},
                (proxy, method, args) -> {
                    if ("bodyToString".equals(method.getName())) return respBody;
                    if ("headerValue".equals(method.getName())) {
                        if (args != null && args.length > 0 && "Content-Type".equalsIgnoreCase((String) args[0])) {
                            return respContentType;
                        }
                    }
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
                    if ("hasResponse".equals(method.getName())) return resp != null;
                    return null;
                }
        );
    }

    @Test
    public void testJsonParameterExtractionAndDeduplication() {
        ParameterScanner_littlespidy scanner = new ParameterScanner_littlespidy();
        Map<String, ParameterEntry_littlespidy> map = new LinkedHashMap<>();

        String reqJson = "{\"email\":\"user@example.com\",\"password\":\"p@ssword\",\"profile\":{\"role\":\"admin\"}}";
        String respJson = "{\"email\":\"user@example.com\",\"token\":\"jwt.token.val\",\"expires_in\":3600}";

        HttpRequestResponse item = createMockItem(reqJson, "application/json", respJson, "application/json");
        scanner.scanItem(item, map);

        // Parameters expected: email, password, profile, role, token, expires_in
        assertTrue(map.containsKey("email"));
        assertTrue(map.containsKey("password"));
        assertTrue(map.containsKey("role"));
        assertTrue(map.containsKey("token"));
        assertTrue(map.containsKey("expires_in"));

        // 'email' was present in both request body and response body -> grouped into one entry
        ParameterEntry_littlespidy emailEntry = map.get("email");
        assertEquals(2, emailEntry.getOccurrenceCount());
        assertEquals("Both", emailEntry.getSourceDisplay());
        assertEquals("JSON", emailEntry.getFormatDisplay());
        assertTrue(emailEntry.getSampleValuesDisplay().contains("user@example.com"));

        // 'password' only in request body
        ParameterEntry_littlespidy passEntry = map.get("password");
        assertEquals(1, passEntry.getOccurrenceCount());
        assertEquals("Request Body", passEntry.getSourceDisplay());

        // 'token' only in response body
        ParameterEntry_littlespidy tokenEntry = map.get("token");
        assertEquals(1, tokenEntry.getOccurrenceCount());
        assertEquals("Response Body", tokenEntry.getSourceDisplay());
    }

    @Test
    public void testFormUrlencodedAndHtmlInputParameters() {
        ParameterScanner_littlespidy scanner = new ParameterScanner_littlespidy();
        Map<String, ParameterEntry_littlespidy> map = new LinkedHashMap<>();

        String reqForm = "item_id=1234&quantity=2&coupon=DISCOUNT10";
        String respHtml = "<html><body><form action='/pay'><input type='hidden' name='csrf_token' value='abcdef123'><input type='text' name='card_number'></form></body></html>";

        HttpRequestResponse item = createMockItem(reqForm, "application/x-www-form-urlencoded", respHtml, "text/html; charset=UTF-8");
        scanner.scanItem(item, map);

        assertTrue(map.containsKey("item_id"));
        assertTrue(map.containsKey("quantity"));
        assertTrue(map.containsKey("coupon"));
        assertTrue(map.containsKey("csrf_token"));
        assertTrue(map.containsKey("card_number"));

        assertEquals("Form", map.get("item_id").getFormatDisplay());
        assertEquals("Request Body", map.get("item_id").getSourceDisplay());

        assertEquals("HTML", map.get("csrf_token").getFormatDisplay());
        assertEquals("Response Body", map.get("csrf_token").getSourceDisplay());
        assertTrue(map.get("csrf_token").getSampleValuesDisplay().contains("abcdef123"));
    }

    @Test
    public void testMultipartParameters() {
        ParameterScanner_littlespidy scanner = new ParameterScanner_littlespidy();
        Map<String, ParameterEntry_littlespidy> map = new LinkedHashMap<>();

        String boundary = "---------------------------974767299852498929531610575";
        String reqMultipart = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"upload_file\"; filename=\"doc.pdf\"\r\n"
                + "Content-Type: application/pdf\r\n\r\n"
                + "%PDF-1.4...\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"description\"\r\n\r\n"
                + "Annual report\r\n"
                + "--" + boundary + "--\r\n";
        String respText = "Uploaded successfully";

        HttpRequestResponse item = createMockItem(reqMultipart, "multipart/form-data; boundary=" + boundary, respText, "text/plain");
        scanner.scanItem(item, map);

        assertTrue(map.containsKey("upload_file"));
        assertTrue(map.containsKey("description"));
        assertEquals("Multipart", map.get("upload_file").getFormatDisplay());
    }
}
