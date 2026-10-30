// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import com.littlespidy.apiinspector.ui.InputValidationConfigPanel_littlespidy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileWriter;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Big List of Naughty Strings (BLNS) parser and input validation techniques.
 */
public class NaughtyStringsTest_littlespidy {

    @Test
    @DisplayName("Verify NaughtyStringsParser loads payloads across retained BLNS categories")
    void testLoadDefaultBlnsTechniques() {
        List<InputValidationTechnique_littlespidy> blnsTechs = NaughtyStringsParser_littlespidy.loadDefaultBlnsTechniques();
        assertNotNull(blnsTechs, "BLNS techniques list must not be null");
        assertFalse(blnsTechs.isEmpty(), "BLNS techniques list must not be empty");
        assertEquals(4, blnsTechs.size(), "Must contain 4 structured BLNS groups");

        int totalPayloads = 0;
        for (InputValidationTechnique_littlespidy t : blnsTechs) {
            assertTrue(t.isBlns(), "All loaded techniques must be marked as BLNS");
            assertTrue(t.getPayloadCount() > 0, "Each technique must have payloads");
            totalPayloads += t.getPayloadCount();
        }

        assertTrue(totalPayloads >= 180, "Must load at least 180 total retained naughty string payloads, found: " + totalPayloads);

        // Verify specific key groups
        InputValidationTechnique_littlespidy reserved = blnsTechs.stream()
                .filter(t -> "blns_reserved".equals(t.getId())).findFirst().orElse(null);
        assertNotNull(reserved);
        assertTrue(reserved.getSamplePayloads().contains("undefined"));
        assertTrue(reserved.getSamplePayloads().contains("null"));

        InputValidationTechnique_littlespidy numeric = blnsTechs.stream()
                .filter(t -> "blns_numeric".equals(t.getId())).findFirst().orElse(null);
        assertNotNull(numeric);
        assertTrue(numeric.getSamplePayloads().contains("0"));
        assertTrue(numeric.getSamplePayloads().contains("-1"));
        assertTrue(numeric.getSamplePayloads().contains("NaN"));

        InputValidationTechnique_littlespidy special = blnsTechs.stream()
                .filter(t -> "blns_special".equals(t.getId())).findFirst().orElse(null);
        assertNotNull(special);

        InputValidationTechnique_littlespidy unicode = blnsTechs.stream()
                .filter(t -> "blns_unicode".equals(t.getId())).findFirst().orElse(null);
        assertNotNull(unicode);
    }

    @Test
    @DisplayName("Verify parseCustomFile creates technique from arbitrary wordlist file")
    void testParseCustomFile() throws Exception {
        File tempWordlist = File.createTempFile("test_wordlist_", ".txt");
        tempWordlist.deleteOnExit();

        try (FileWriter fw = new FileWriter(tempWordlist)) {
            fw.write("# Comment line\n");
            fw.write("admin_probe\n");
            fw.write("secret_override\n");
            fw.write("test_boundary\n");
        }

        InputValidationTechnique_littlespidy custom = NaughtyStringsParser_littlespidy.parseCustomFile(tempWordlist);
        assertNotNull(custom);
        assertEquals(3, custom.getPayloadCount());
        assertTrue(custom.getSamplePayloads().contains("admin_probe"));
        assertTrue(custom.getSamplePayloads().contains("secret_override"));
    }

    @Test
    @DisplayName("Verify InputValidationTechnique getDefaultTechniques returns the 4 BLNS categories from JSON")
    void testCombinedTechniques() {
        List<InputValidationTechnique_littlespidy> all = InputValidationTechnique_littlespidy.getDefaultTechniques();
        assertEquals(4, all.size(), "Default techniques should contain the 4 BLNS categories");
        assertTrue(all.stream().allMatch(InputValidationTechnique_littlespidy::isBlns), "All categories should be BLNS categories");
    }

    @Test
    @DisplayName("Verify InputValidationConfigPanel filtering and table model")
    void testConfigPanelFiltering() {
        InputValidationConfigPanel_littlespidy panel = new InputValidationConfigPanel_littlespidy(null);
        List<InputValidationTechnique_littlespidy> techs = panel.getTechniques();
        assertEquals(4, techs.size(), "Panel should have 4 pure BLNS techniques initially");

        // Verify individual payloads table contains 180+ individual items
        List<InputValidationPayloadItem_littlespidy> payloads = panel.getPayloadItems();
        assertNotNull(payloads);
        assertTrue(payloads.size() >= 180, "Must contain at least 180 individual payloads, found: " + payloads.size());
    }

    @Test
    @DisplayName("Verify loadAllIndividualPayloads loads 180+ distinct payload rows with signatures")
    void testLoadAllIndividualPayloads() {
        List<InputValidationPayloadItem_littlespidy> items = NaughtyStringsParser_littlespidy.loadAllIndividualPayloads();
        assertNotNull(items);
        assertTrue(items.size() >= 180, "Must load 180+ individual payloads, found: " + items.size());

        // Check that every item has non-empty ID, Category
        boolean foundUndefined = false;
        boolean foundNull = false;
        boolean foundZero = false;

        for (InputValidationPayloadItem_littlespidy item : items) {
            assertNotNull(item.getId());
            assertFalse(item.getId().isBlank());
            assertNotNull(item.getCategory());
            assertFalse(item.getCategory().isBlank());
            assertTrue(item.isEnabled());

            if ("undefined".equals(item.getPayload())) foundUndefined = true;
            if ("null".equals(item.getPayload())) foundNull = true;
            if ("0".equals(item.getPayload())) foundZero = true;
        }

        assertTrue(foundUndefined, "Must contain 'undefined' payload");
        assertTrue(foundNull, "Must contain 'null' payload");
        assertTrue(foundZero, "Must contain '0' payload");
    }

    @Test
    @DisplayName("Verify parseCustomFileToPayloads creates individual payload items")
    void testParseCustomFileToPayloads() throws Exception {
        File tempWordlist = File.createTempFile("test_individual_wordlist_", ".txt");
        tempWordlist.deleteOnExit();

        try (FileWriter fw = new FileWriter(tempWordlist)) {
            fw.write("# Comment line\n");
            fw.write("custom_payload_alpha\n");
            fw.write("custom_payload_beta\n");
            fw.write("custom_payload_gamma\n");
        }

        List<InputValidationPayloadItem_littlespidy> items = NaughtyStringsParser_littlespidy.parseCustomFileToPayloads(tempWordlist);
        assertNotNull(items);
        assertEquals(3, items.size());
        assertEquals("custom_payload_alpha", items.get(0).getPayload());
        assertEquals("custom_payload_beta", items.get(1).getPayload());
        assertEquals("custom_payload_gamma", items.get(2).getPayload());
        assertTrue(items.get(0).isCustom());
    }
}
