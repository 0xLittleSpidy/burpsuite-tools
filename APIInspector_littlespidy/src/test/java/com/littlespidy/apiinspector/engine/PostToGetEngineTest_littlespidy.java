// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.apiinspector.TestMockHelper_littlespidy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class PostToGetEngineTest_littlespidy {

    @Test
    @DisplayName("Extract body parameters from JSON request")
    public void testExtractJsonParameters() {
        String jsonBody = "{\"username\": \"admin\", \"role\": \"superuser\", \"active\": true, \"age\": 30}";
        HttpRequest req = TestMockHelper_littlespidy.createMockRequest(
                "POST", "https://example.com/api/v1/users", "/api/v1/users",
                Map.of("Content-Type", "application/json"), jsonBody
        );

        Map<String, String> params = PostToGetEngine_littlespidy.extractBodyParameters(req);
        assertNotNull(params);
        assertEquals("admin", params.get("username"));
        assertEquals("superuser", params.get("role"));
        assertEquals("true", params.get("active"));
        assertEquals("30", params.get("age"));
    }

    @Test
    @DisplayName("Extract body parameters from URL encoded form request")
    public void testExtractFormParameters() {
        String formBody = "action=create&item_id=42&category=electronics";
        HttpRequest req = TestMockHelper_littlespidy.createMockRequest(
                "POST", "https://example.com/api/v1/items", "/api/v1/items",
                Map.of("Content-Type", "application/x-www-form-urlencoded"), formBody
        );

        Map<String, String> params = PostToGetEngine_littlespidy.extractBodyParameters(req);
        assertNotNull(params);
        assertEquals("create", params.get("action"));
        assertEquals("42", params.get("item_id"));
        assertEquals("electronics", params.get("category"));
    }

    @Test
    @DisplayName("Convert POST request to GET with query string")
    public void testBuildGetRequest() {
        HttpRequest req = TestMockHelper_littlespidy.createMockRequest(
                "POST", "https://example.com/api/v1/search", "/api/v1/search",
                Map.of("Content-Type", "application/json", "Content-Length", "28"),
                "{\"query\": \"vuln\", \"limit\": \"10\"}"
        );

        Map<String, String> params = PostToGetEngine_littlespidy.extractBodyParameters(req);
        HttpRequest getReq = PostToGetEngine_littlespidy.buildGetRequest(req, params);

        assertNotNull(getReq);
        assertEquals("GET", getReq.method());
        assertTrue(getReq.path().contains("query=vuln"));
        assertTrue(getReq.path().contains("limit=10"));
        assertEquals(0, getReq.body().length());
        assertFalse(getReq.hasHeader("Content-Type"));
        assertFalse(getReq.hasHeader("Content-Length"));
    }

    @Test
    @DisplayName("Evaluate verdicts for POST to GET outcomes")
    public void testEvaluateVerdict() {
        // Method tampering accepted (200 to 200)
        assertEquals("Method Tampering Accepted (Status Match 200)",
                PostToGetEngine_littlespidy.evaluateVerdict(200, 500, 200, 500));

        // 405 Method Not Allowed
        assertEquals("Protected (405 Method Not Allowed)",
                PostToGetEngine_littlespidy.evaluateVerdict(200, 500, 405, 120));

        // 403 Forbidden / Auth enforced
        assertEquals("Auth Enforced (Status 403)",
                PostToGetEngine_littlespidy.evaluateVerdict(200, 500, 403, 100));

        // 404 Not Found
        assertEquals("Status 404 (Diff -420B)",
                PostToGetEngine_littlespidy.evaluateVerdict(200, 500, 404, 80));
    }

    @Test
    @DisplayName("Verify pause and resume states")
    public void testPauseResumeState() {
        PostToGetEngine_littlespidy engine = new PostToGetEngine_littlespidy(null);
        assertFalse(engine.isPaused());
        assertFalse(engine.isCancelled());

        engine.pause();
        assertTrue(engine.isPaused());

        engine.resume();
        assertFalse(engine.isPaused());

        engine.cancel();
        assertTrue(engine.isCancelled());
    }
}
