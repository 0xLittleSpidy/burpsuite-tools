// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import com.google.gson.Gson;
import com.littlespidy.jssourcemapexplorer.model.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying finding classification (True Positive, False Positive, Not Classified),
 * record mutation methods, filtering logic, and JSON session serialization.
 *
 * @author littlespidy
 */
class FindingClassificationTest_littlespidy {

    private final Gson gson = new Gson();

    @Test
    @DisplayName("Verify default classification is Not Classified across all finding models")
    void testDefaultClassificationIsNotClassified() {
        DiscoveredEndpoint ep = new DiscoveredEndpoint("https://target.com/app.js", "JS File", "/api/v1/users", "GET", 10, "let x = 1;", "Regex");
        assertEquals("Not Classified", ep.classification());

        DiscoveredSecret sec = new DiscoveredSecret("https://target.com/app.js", "JS File", "AWS Access Key", "AKIAIOSFODNN7EXAMPLE", 3.8, "High", "Regex", 15, "let key = 'AKIA...'");
        assertEquals("Not Classified", sec.classification());

        DiscoveredComment comm = new DiscoveredComment("https://target.com/app.js", "JS File", "Single-Line (//)", "TODO / FIXME", "// TODO: remove debug endpoint", 20, "// TODO...");
        assertEquals("Not Classified", comm.classification());

        DiscoveredSecurityBypass bypass = new DiscoveredSecurityBypass("https://target.com/app.js", "JS File", "Angular", "bypassSecurityTrustHtml", "Critical", "High", 25, "sanitizer.bypass...", "Bypass DomSanitizer");
        assertEquals("Not Classified", bypass.classification());

        DiscoveredCloudUrl cu = new DiscoveredCloudUrl("https://target.com/app.js", "JS File", "AWS", "mybucket.s3.amazonaws.com", 30, "https://mybucket...");
        assertEquals("Not Classified", cu.classification());

        DiscoveredDependency dep = new DiscoveredDependency("https://target.com/app.js", "JS File", "internal-auth-lib", "1.0.0", "package.json", "Unverified", "-", 1, 0, 0, "internal-auth-lib");
        assertEquals("Not Classified", dep.getClassification());
    }

    @Test
    @DisplayName("Verify withClassification creates updated copies with TP and FP tags")
    void testWithClassification() {
        DiscoveredEndpoint ep = new DiscoveredEndpoint("https://target.com/app.js", "JS File", "/api/v1/users", "GET", 10, "let x = 1;", "Regex");
        DiscoveredEndpoint tpEp = ep.withClassification("True Positive");
        assertEquals("True Positive", tpEp.classification());
        assertEquals(ep.endpoint(), tpEp.endpoint());

        DiscoveredEndpoint fpEp = ep.withClassification("False Positive");
        assertEquals("False Positive", fpEp.classification());

        DiscoveredSecret sec = new DiscoveredSecret("https://target.com/app.js", "JS File", "AWS Access Key", "AKIAIOSFODNN7EXAMPLE", 3.8, "High", "Regex", 15, "let key = 'AKIA...'");
        DiscoveredSecret tpSec = sec.withClassification("True Positive");
        assertEquals("True Positive", tpSec.classification());

        DiscoveredComment comm = new DiscoveredComment("https://target.com/app.js", "JS File", "Single-Line (//)", "TODO / FIXME", "// TODO", 20, "// TODO");
        DiscoveredComment fpComm = comm.withClassification("False Positive");
        assertEquals("False Positive", fpComm.classification());

        DiscoveredSecurityBypass bypass = new DiscoveredSecurityBypass("https://target.com/app.js", "JS File", "React", "dangerouslySetInnerHTML", "Critical", "High", 12, "dangerouslySetInnerHTML", "React XSS Sink");
        DiscoveredSecurityBypass tpBypass = bypass.withClassification("True Positive");
        assertEquals("True Positive", tpBypass.classification());

        DiscoveredCloudUrl cu = new DiscoveredCloudUrl("https://target.com/app.js", "JS File", "AWS", "mybucket.s3.amazonaws.com", 30, "mybucket");
        DiscoveredCloudUrl fpCu = cu.withClassification("False Positive");
        assertEquals("False Positive", fpCu.classification());

        DiscoveredDependency dep = new DiscoveredDependency("https://target.com/app.js", "JS File", "internal-auth-lib", "1.0.0", "package.json", "Unverified", "-", 1, 0, 0, "internal-auth-lib");
        dep.setClassification("True Positive");
        assertEquals("True Positive", dep.getClassification());
    }

    @Test
    @DisplayName("Verify Gson JSON serialization preserves classification")
    void testJsonSerializationPreservesClassification() {
        DiscoveredEndpoint ep = new DiscoveredEndpoint("https://target.com/app.js", "JS File", "/api/v1/users", "GET", 10, 0, 0, "let x = 1;", "Regex", "True Positive");
        String json = gson.toJson(ep);
        assertTrue(json.contains("\"classification\":\"True Positive\""));

        DiscoveredEndpoint deserialized = gson.fromJson(json, DiscoveredEndpoint.class);
        assertEquals("True Positive", deserialized.classification());
        assertEquals(ep.endpoint(), deserialized.endpoint());

        DiscoveredSecret sec = new DiscoveredSecret("https://target.com/app.js", "JS File", "API Key", "xyz123", "High", 3.5, "High", "Regex", 1, 0, 0, "xyz123", "False Positive");
        String secJson = gson.toJson(sec);
        assertTrue(secJson.contains("\"classification\":\"False Positive\""));

        DiscoveredSecret secDeserialized = gson.fromJson(secJson, DiscoveredSecret.class);
        assertEquals("False Positive", secDeserialized.classification());
    }

    @Test
    @DisplayName("Verify classification filtering logic")
    void testClassificationFilteringLogic() {
        DiscoveredEndpoint tp = new DiscoveredEndpoint("https://target.com/app.js", "JS File", "/tp", "GET", 1, 0, 0, "GET /tp", "Regex", "True Positive");
        DiscoveredEndpoint fp = new DiscoveredEndpoint("https://target.com/app.js", "JS File", "/fp", "GET", 2, 0, 0, "GET /fp", "Regex", "False Positive");
        DiscoveredEndpoint nc = new DiscoveredEndpoint("https://target.com/app.js", "JS File", "/nc", "GET", 3, 0, 0, "GET /nc", "Regex", "Not Classified");

        List<DiscoveredEndpoint> all = List.of(tp, fp, nc);

        // Filter: only True Positive
        Set<String> tpFilter = Set.of("True Positive");
        List<DiscoveredEndpoint> tpOnly = all.stream().filter(e -> tpFilter.contains(e.classification())).toList();
        assertEquals(1, tpOnly.size());
        assertEquals("/tp", tpOnly.get(0).endpoint());

        // Filter: True Positive + False Positive
        Set<String> classifiedFilter = Set.of("True Positive", "False Positive");
        List<DiscoveredEndpoint> classifiedOnly = all.stream().filter(e -> classifiedFilter.contains(e.classification())).toList();
        assertEquals(2, classifiedOnly.size());

        // Filter: Not Classified
        Set<String> ncFilter = Set.of("Not Classified");
        List<DiscoveredEndpoint> ncOnly = all.stream().filter(e -> ncFilter.contains(e.classification())).toList();
        assertEquals(1, ncOnly.size());
        assertEquals("/nc", ncOnly.get(0).endpoint());
    }
}
