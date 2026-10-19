// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.persistence;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.littlespidy.apiinspector.model.*;
import com.littlespidy.apiinspector.persistence.SessionStateDTO_littlespidy.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AuthPersistenceTest_littlespidy {

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    @Test
    @DisplayName("Verify round-trip JSON serialization of collections, profiles, and test results")
    public void testAuthSessionStateRoundTrip(@TempDir Path tempDir) throws Exception {
        SessionRootDTO root = new SessionRootDTO();
        root.version = 2;
        root.savedAt = System.currentTimeMillis();

        // 1. Create Collection
        ImportedCollection_littlespidy col = new ImportedCollection_littlespidy(
                "Orders API",
                "OpenAPI 3.0",
                "FILE",
                "/tmp/orders.json"
        );
        col.setTargetBaseUrl("https://orders.example.com");
        col.setAssignedProfileId("prof-123");

        DiscoveredEndpoint_littlespidy ep = new DiscoveredEndpoint_littlespidy("GET", "/orders/{id}", "Get Order");
        ep.setPathParams(Map.of("id", "101"));
        ep.setQueryParams(Map.of("fields", "all"));
        ep.setHeaders(Map.of("Accept", "application/json"));
        ep.setRequiresAuth(true);
        col.getEndpoints().add(ep);

        ImportedCollectionDTO colDto = APIInspectorPersistenceManager_littlespidy.serializeImportedCollection(col);
        root.importedCollections.add(colDto);

        // 2. Create Profile
        AuthProfile_littlespidy prof = new AuthProfile_littlespidy("Orders Bearer", AuthType_littlespidy.BEARER_TOKEN);
        prof.setId("prof-123");
        prof.setBearerToken("secret_token_abc");
        prof.setTestUnauthenticatedComparison(true);

        AuthProfileDTO profDto = APIInspectorPersistenceManager_littlespidy.serializeAuthProfile(prof);
        root.authProfiles.add(profDto);

        // 3. Create Test Result
        AuthTestResult_littlespidy res = new AuthTestResult_littlespidy();
        res.setCollectionId(col.getId());
        res.setCollectionName(col.getName());
        res.setMethod("GET");
        res.setPath("/orders/{id}");
        res.setFullUrl("https://orders.example.com/orders/101");
        res.setProfileId(prof.getId());
        res.setProfileName(prof.getName());
        res.setAuthStatusCode(200);
        res.setAuthResponseLength(1024);
        res.setAuthLatencyMs(65);
        res.setUnauthStatusCode(401);
        res.setUnauthResponseLength(80);
        res.setUnauthLatencyMs(45);
        res.setOutcome(AuthTestOutcome_littlespidy.AUTHENTICATED_ONLY);
        res.setTimestamp(System.currentTimeMillis());

        AuthTestResultDTO resDto = APIInspectorPersistenceManager_littlespidy.serializeAuthTestResult(res);
        root.authTestResults.add(resDto);

        // Serialize to JSON
        String json = gson.toJson(root);
        assertNotNull(json);
        assertTrue(json.contains("Orders API"));
        assertTrue(json.contains("Orders Bearer"));
        assertTrue(json.contains("AUTHENTICATED_ONLY"));

        // Write and read back
        File sessionFile = tempDir.resolve("api_inspector_session.json").toFile();
        Files.writeString(sessionFile.toPath(), json, StandardCharsets.UTF_8);

        String readJson = Files.readString(sessionFile.toPath(), StandardCharsets.UTF_8);
        SessionRootDTO deserialized = gson.fromJson(readJson, SessionRootDTO.class);
        assertNotNull(deserialized);

        // Verify Collection
        assertEquals(1, deserialized.importedCollections.size());
        ImportedCollection_littlespidy restoredCol = APIInspectorPersistenceManager_littlespidy.deserializeImportedCollection(deserialized.importedCollections.get(0));
        assertNotNull(restoredCol);
        assertEquals("Orders API", restoredCol.getName());
        assertEquals("https://orders.example.com", restoredCol.getTargetBaseUrl());
        assertEquals("prof-123", restoredCol.getAssignedProfileId());
        assertEquals(1, restoredCol.getEndpointCount());
        assertEquals("/orders/{id}", restoredCol.getEndpoints().get(0).getPath());

        // Verify Profile
        assertEquals(1, deserialized.authProfiles.size());
        AuthProfile_littlespidy restoredProf = APIInspectorPersistenceManager_littlespidy.deserializeAuthProfile(deserialized.authProfiles.get(0));
        assertNotNull(restoredProf);
        assertEquals("Orders Bearer", restoredProf.getName());
        assertEquals("secret_token_abc", restoredProf.getBearerToken());
        assertTrue(restoredProf.isTestUnauthenticatedComparison());

        // Verify Test Result
        assertEquals(1, deserialized.authTestResults.size());
        AuthTestResult_littlespidy restoredRes = APIInspectorPersistenceManager_littlespidy.deserializeAuthTestResult(deserialized.authTestResults.get(0));
        assertNotNull(restoredRes);
        assertEquals(200, restoredRes.getAuthStatusCode());
        assertEquals(401, restoredRes.getUnauthStatusCode());
        assertEquals(AuthTestOutcome_littlespidy.AUTHENTICATED_ONLY, restoredRes.getOutcome());
    }
}
