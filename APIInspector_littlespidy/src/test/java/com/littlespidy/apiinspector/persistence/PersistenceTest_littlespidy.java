// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.persistence;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.apiinspector.TestMockHelper_littlespidy;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class PersistenceTest_littlespidy {

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    @Test
    public void testHttpMessageDtoSerialization() {
        HttpRequest req = TestMockHelper_littlespidy.createMockRequest(
                "GET",
                "https://api.example.com/v1/users",
                "/api/v1/users",
                Map.of("Host", "api.example.com"),
                ""
        );

        HttpMessageDTO dto = APIInspectorPersistenceManager_littlespidy.serializeHttpRequest(req);
        assertNotNull(dto);
        assertEquals("example.com", dto.host);
        assertEquals(443, dto.port);
        assertTrue(dto.secure);
        assertNotNull(dto.base64Bytes);

        HttpResponse resp = TestMockHelper_littlespidy.createMockResponse(200, Map.of("Content-Type", "application/json"), "{\"status\":\"ok\"}");
        HttpMessageDTO respDto = APIInspectorPersistenceManager_littlespidy.serializeHttpResponse(resp, req.httpService());
        assertNotNull(respDto);
        assertEquals((short) 200, resp.statusCode());
        assertNotNull(respDto.base64Bytes);
    }

    @Test
    public void testSessionStateJsonRoundTrip(@TempDir Path tempDir) throws Exception {
        SessionRootDTO root = new SessionRootDTO();
        root.savedAt = System.currentTimeMillis();

        SessionTabDTO tab = new SessionTabDTO();
        tab.tabTitle = "#1 GET /api/v1/users";
        tab.targetUrl = "https://api.example.com/v1/users";
        tab.method = "GET";
        tab.candidates = "1, 2, 3, beta";
        tab.threads = 8;
        tab.delayMs = 100;
        tab.strategies.uriPath = true;
        tab.strategies.headers = true;
        tab.strategies.queryParams = false;

        ProbeResultDTO pr = new ProbeResultDTO();
        pr.id = 1;
        pr.strategyName = "URI Path";
        pr.variation = "/api/v2/users";
        pr.statusCode = 200;
        pr.responseLength = 1420;
        pr.mimeType = "JSON";
        pr.diffAnalysis = "ACTIVE ALTERNATIVE (+120 B)";
        pr.latencyMs = 85;

        tab.results.add(pr);
        root.tabs.add(tab);

        // Serialize to JSON
        String json = gson.toJson(root);
        assertNotNull(json);
        assertTrue(json.contains("#1 GET /api/v1/users"));
        assertTrue(json.contains("/api/v2/users"));

        // Write to temp file and read back
        File sessionFile = tempDir.resolve("test_session.json").toFile();
        Files.writeString(sessionFile.toPath(), json, StandardCharsets.UTF_8);
        assertTrue(sessionFile.exists());

        String readJson = Files.readString(sessionFile.toPath(), StandardCharsets.UTF_8);
        SessionRootDTO deserialized = gson.fromJson(readJson, SessionRootDTO.class);

        assertNotNull(deserialized);
        assertEquals(1, deserialized.tabs.size());
        SessionTabDTO restoredTab = deserialized.tabs.get(0);
        assertEquals("#1 GET /api/v1/users", restoredTab.tabTitle);
        assertEquals("1, 2, 3, beta", restoredTab.candidates);
        assertEquals(8, restoredTab.threads);
        assertEquals(100, restoredTab.delayMs);
        assertTrue(restoredTab.strategies.uriPath);
        assertTrue(restoredTab.strategies.headers);
        assertFalse(restoredTab.strategies.queryParams);

        assertEquals(1, restoredTab.results.size());
        ProbeResultDTO restoredPr = restoredTab.results.get(0);
        assertEquals(1, restoredPr.id);
        assertEquals("URI Path", restoredPr.strategyName);
        assertEquals("/api/v2/users", restoredPr.variation);
        assertEquals(200, restoredPr.statusCode);
        assertEquals(1420, restoredPr.responseLength);
    }
}
