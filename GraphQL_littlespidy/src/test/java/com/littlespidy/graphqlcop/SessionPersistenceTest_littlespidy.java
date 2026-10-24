// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.littlespidy.graphqlcop.model.AuditFinding_littlespidy;
import com.littlespidy.graphqlcop.model.AuditProbeType_littlespidy;
import com.littlespidy.graphqlcop.model.AuditSeverity_littlespidy;
import com.littlespidy.graphqlcop.model.SessionData_littlespidy;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Type;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SessionPersistenceTest_littlespidy {

    @Test
    public void testSessionSerializationRoundtrip() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        SessionData_littlespidy session = new SessionData_littlespidy("test-id", "Target App", "https://api.target.com/graphql");
        session.setCustomHeaders("Authorization: Bearer test_token\nX-API-Key: 12345");

        AuditFinding_littlespidy finding = new AuditFinding_littlespidy(
                "f1",
                AuditProbeType_littlespidy.INTROSPECTION,
                AuditSeverity_littlespidy.HIGH,
                "Introspection Enabled",
                "Schema exposed",
                "Disable introspection",
                "High impact",
                "https://api.target.com/graphql",
                "cmVxdWVzdA==",
                "cmVzcG9uc2U="
        );
        session.setFindings(Collections.singletonList(finding));

        Type type = new TypeToken<List<SessionData_littlespidy>>(){}.getType();
        String json = gson.toJson(Collections.singletonList(session), type);

        assertNotNull(json);
        List<SessionData_littlespidy> restored = gson.fromJson(json, type);
        assertEquals(1, restored.size());

        SessionData_littlespidy rSession = restored.get(0);
        assertEquals("test-id", rSession.getSessionId());
        assertEquals("Target App", rSession.getTabTitle());
        assertEquals("https://api.target.com/graphql", rSession.getTargetUrl());
        assertTrue(rSession.getCustomHeaders().contains("Bearer test_token"));
        assertEquals(1, rSession.getFindings().size());
        assertEquals(AuditSeverity_littlespidy.HIGH, rSession.getFindings().get(0).getSeverity());
    }
}
