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
    @DisplayName("Verify NaughtyStringsParser loads 500+ payloads across 10 BLNS categories")
    void testLoadDefaultBlnsTechniques() {
        List<InputValidationTechnique_littlespidy> blnsTechs = NaughtyStringsParser_littlespidy.loadDefaultBlnsTechniques();
        assertNotNull(blnsTechs, "BLNS techniques list must not be null");
        assertFalse(blnsTechs.isEmpty(), "BLNS techniques list must not be empty");
        assertTrue(blnsTechs.size() >= 9, "Must contain at least 9 BLNS groups");

        int totalPayloads = 0;
        for (InputValidationTechnique_littlespidy t : blnsTechs) {
            assertTrue(t.isBlns(), "All loaded techniques must be marked as BLNS");
            assertTrue(t.getPayloadCount() > 0, "Each technique must have payloads");
            totalPayloads += t.getPayloadCount();
        }

        assertTrue(totalPayloads >= 400, "Must load at least 400 total naughty string payloads, found: " + totalPayloads);

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

        InputValidationTechnique_littlespidy msdos = blnsTechs.stream()
                .filter(t -> "blns_msdos".equals(t.getId())).findFirst().orElse(null);
        assertNotNull(msdos);
        assertTrue(msdos.getSamplePayloads().contains("CON") || msdos.getSamplePayloads().contains("PRN"));
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
    @DisplayName("Verify InputValidationTechnique getDefaultTechniques combines standard and BLNS")
    void testCombinedTechniques() {
        List<InputValidationTechnique_littlespidy> all = InputValidationTechnique_littlespidy.getDefaultTechniques();
        assertTrue(all.size() >= 15, "Default techniques should combine 6 standard + 9+ BLNS categories");

        long standardCount = all.stream().filter(t -> !t.isBlns()).count();
        long blnsCount = all.stream().filter(t -> t.isBlns()).count();

        assertEquals(6, standardCount, "Should have 6 standard OWASP categories");
        assertTrue(blnsCount >= 9, "Should have at least 9 BLNS categories");
    }

    @Test
    @DisplayName("Verify InputValidationConfigPanel filtering and table model")
    void testConfigPanelFiltering() {
        InputValidationConfigPanel_littlespidy panel = new InputValidationConfigPanel_littlespidy(null);
        List<InputValidationTechnique_littlespidy> techs = panel.getTechniques();
        assertTrue(techs.size() >= 15, "Panel should have all combined techniques initially");
    }
}
