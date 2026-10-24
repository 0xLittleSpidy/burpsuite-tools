// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.session;

import com.google.gson.Gson;
import com.littlespidy.wayback.model.DirectoryFinding_littlespidy;
import com.littlespidy.wayback.model.DiscoveredPath_littlespidy;
import com.littlespidy.wayback.model.DiscoveredSubdomain_littlespidy;
import com.littlespidy.wayback.session.SessionData_littlespidy.CommonConfigData;
import com.littlespidy.wayback.session.SessionData_littlespidy.DomainSessionState_littlespidy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SessionManagerTest_littlespidy {

    @Test
    public void testSessionDataSerializationAndDeserialization() {
        SessionData_littlespidy original = new SessionData_littlespidy();
        original.setSavedTimestamp("2026-10-24T10:00:00");

        CommonConfigData cData = new CommonConfigData();
        cData.userAgent = "TestBrowser/1.0";
        cData.cdxRetries = 4;
        cData.signatures = List.of("Index of /", "Directory Listing for");
        original.setCommonConfig(cData);

        DomainSessionState_littlespidy dState = new DomainSessionState_littlespidy();
        dState.domain = "testphp.vulnweb.com";
        dState.paths.add(new DiscoveredPath_littlespidy("testphp.vulnweb.com", "/admin/"));
        dState.subdomains.add(new DiscoveredSubdomain_littlespidy("api.vulnweb.com", 12));

        DirectoryFinding_littlespidy finding = new DirectoryFinding_littlespidy(
                1, "HTTP", "testphp.vulnweb.com", "/admin/",
                "http://testphp.vulnweb.com/admin/", 200, "Index of /", 1234, "10:00:00",
                null, null
        );
        finding.setRawRequestBase64("R0VUIC9hZG1pbi8gSFRUUC8xLjENCg0K");
        dState.findings.add(finding);

        original.getDomains().add(dState);

        Gson gson = new Gson();
        String json = gson.toJson(original);
        assertNotNull(json);

        SessionData_littlespidy restored = gson.fromJson(json, SessionData_littlespidy.class);
        assertNotNull(restored);
        assertEquals("2026-10-24T10:00:00", restored.getSavedTimestamp());
        assertEquals("TestBrowser/1.0", restored.getCommonConfig().userAgent);
        assertEquals(4, restored.getCommonConfig().cdxRetries);
        assertEquals(1, restored.getDomains().size());

        DomainSessionState_littlespidy restoredDomain = restored.getDomains().get(0);
        assertEquals("testphp.vulnweb.com", restoredDomain.domain);
        assertEquals(1, restoredDomain.paths.size());
        assertEquals("/admin/", restoredDomain.paths.get(0).getPath());
        assertEquals(1, restoredDomain.findings.size());
        assertEquals("R0VUIC9hZG1pbi8gSFRUUC8xLjENCg0K", restoredDomain.findings.get(0).getRawRequestBase64());
    }
}
