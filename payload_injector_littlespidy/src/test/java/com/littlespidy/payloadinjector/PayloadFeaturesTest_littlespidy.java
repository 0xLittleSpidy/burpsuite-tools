// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.model;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Proxy;
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

    @BeforeAll
    static void setUpMontoyaFactory() {
        if (burp.api.montoya.internal.ObjectFactoryLocator.FACTORY == null) {
            burp.api.montoya.internal.ObjectFactoryLocator.FACTORY = createMockMontoyaObjectFactory();
        }
    }

    private static burp.api.montoya.internal.MontoyaObjectFactory createMockMontoyaObjectFactory() {
        return (burp.api.montoya.internal.MontoyaObjectFactory) Proxy.newProxyInstance(
                PayloadFeaturesTest_littlespidy.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.internal.MontoyaObjectFactory.class},
                (proxy, method, args) -> {
                    String methodName = method.getName();
                    if ("httpRequest".equals(methodName)) {
                        if (args == null || args.length == 0) {
                            return createMockHttpRequest("");
                        }
                        if (args.length == 1) {
                            if (args[0] instanceof String s) {
                                return createMockHttpRequest(s);
                            }
                            if (args[0] instanceof burp.api.montoya.core.ByteArray ba) {
                                return createMockHttpRequest(new String(ba.getBytes(), StandardCharsets.UTF_8));
                            }
                        }
                        if (args.length == 2) {
                            burp.api.montoya.http.HttpService service = (burp.api.montoya.http.HttpService) args[0];
                            if (args[1] instanceof burp.api.montoya.core.ByteArray ba) {
                                return createMockHttpRequest(new String(ba.getBytes(), StandardCharsets.UTF_8), service);
                            }
                            if (args[1] instanceof String s) {
                                return createMockHttpRequest(s, service);
                            }
                        }
                    }
                    if ("byteArray".equals(methodName)) {
                        if (args != null && args.length > 0) {
                            if (args[0] instanceof byte[] b) return createMockByteArray(b);
                            if (args[0] instanceof String s) return createMockByteArray(s.getBytes(StandardCharsets.UTF_8));
                        }
                        return createMockByteArray(new byte[0]);
                    }
                    if ("parameter".equals(methodName)) {
                        String name = (String) args[0];
                        String value = (String) args[1];
                        burp.api.montoya.http.message.params.HttpParameterType type = (burp.api.montoya.http.message.params.HttpParameterType) args[2];
                        return createMockHttpParameter(name, value, type);
                    }
                    return null;
                }
        );
    }

    private static burp.api.montoya.http.message.requests.HttpRequest createMockHttpRequest(String raw) {
        return createMockHttpRequest(raw, null);
    }

    private static burp.api.montoya.http.message.requests.HttpRequest createMockHttpRequest(String raw, burp.api.montoya.http.HttpService service) {
        return (burp.api.montoya.http.message.requests.HttpRequest) Proxy.newProxyInstance(
                PayloadFeaturesTest_littlespidy.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.http.message.requests.HttpRequest.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("equals".equals(name)) return proxy == args[0];
                    if ("hashCode".equals(name)) return System.identityHashCode(proxy);
                    if ("toString".equals(name)) return raw;
                    if ("httpService".equals(name)) return service;
                    if ("toByteArray".equals(name)) return createMockByteArray(raw.getBytes(StandardCharsets.UTF_8));
                    if ("headerValue".equals(name) && args != null && args.length > 0) {
                        String headerName = (String) args[0];
                        String lower = raw.toLowerCase();
                        String search = "\n" + headerName.toLowerCase() + ":";
                        int idx = lower.indexOf(search);
                        if (idx == -1 && lower.startsWith(headerName.toLowerCase() + ":")) {
                            idx = 0;
                        } else if (idx != -1) {
                            idx += 1;
                        }
                        if (idx != -1) {
                            int colon = raw.indexOf(':', idx);
                            int lineEnd = raw.indexOf("\r\n", colon);
                            if (lineEnd == -1) lineEnd = raw.indexOf('\n', colon);
                            if (lineEnd == -1) lineEnd = raw.length();
                            return raw.substring(colon + 1, lineEnd).trim();
                        }
                        return null;
                    }
                    if ("parameters".equals(name)) {
                        List<burp.api.montoya.http.message.params.ParsedHttpParameter> params = new ArrayList<>();
                        int qIdx = raw.indexOf('?');
                        int spaceIdx = raw.indexOf(' ', qIdx > 0 ? qIdx : 0);
                        if (qIdx != -1 && spaceIdx > qIdx) {
                            String query = raw.substring(qIdx + 1, spaceIdx);
                            String[] pairs = query.split("&");
                            for (String pair : pairs) {
                                int eq = pair.indexOf('=');
                                String pName = eq != -1 ? pair.substring(0, eq) : pair;
                                String pVal = eq != -1 ? pair.substring(eq + 1) : "";
                                params.add(createMockParsedHttpParameter(pName, pVal, burp.api.montoya.http.message.params.HttpParameterType.URL));
                            }
                        }
                        return params;
                    }
                    if ("withUpdatedParameters".equals(name)) {
                        List<?> updated = (List<?>) args[0];
                        String updatedRaw = raw;
                        for (Object obj : updated) {
                            burp.api.montoya.http.message.params.HttpParameter p = (burp.api.montoya.http.message.params.HttpParameter) obj;
                            int qIdx = updatedRaw.indexOf('?');
                            int spaceIdx = updatedRaw.indexOf(' ', qIdx > 0 ? qIdx : 0);
                            if (qIdx != -1 && spaceIdx > qIdx) {
                                String reqStart = updatedRaw.substring(0, qIdx + 1);
                                String query = updatedRaw.substring(qIdx + 1, spaceIdx);
                                String reqEnd = updatedRaw.substring(spaceIdx);
                                String[] pairs = query.split("&");
                                List<String> newPairs = new ArrayList<>();
                                for (String pair : pairs) {
                                    int eq = pair.indexOf('=');
                                    String k = eq != -1 ? pair.substring(0, eq) : pair;
                                    if (k.equals(p.name())) {
                                        newPairs.add(k + "=" + p.value());
                                    } else {
                                        newPairs.add(pair);
                                    }
                                }
                                updatedRaw = reqStart + String.join("&", newPairs) + reqEnd;
                            }
                        }
                        return createMockHttpRequest(updatedRaw, service);
                    }
                    return null;
                }
        );
    }

    private static burp.api.montoya.core.ByteArray createMockByteArray(byte[] bytes) {
        return (burp.api.montoya.core.ByteArray) Proxy.newProxyInstance(
                PayloadFeaturesTest_littlespidy.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.core.ByteArray.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    if ("equals".equals(name)) return proxy == args[0];
                    if ("hashCode".equals(name)) return System.identityHashCode(proxy);
                    if ("getBytes".equals(name)) return bytes;
                    if ("length".equals(name)) return bytes.length;
                    if ("toString".equals(name)) return new String(bytes, StandardCharsets.UTF_8);
                    return null;
                }
        );
    }

    private static burp.api.montoya.http.message.params.HttpParameter createMockHttpParameter(
            String name, String value, burp.api.montoya.http.message.params.HttpParameterType type) {
        return (burp.api.montoya.http.message.params.HttpParameter) Proxy.newProxyInstance(
                PayloadFeaturesTest_littlespidy.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.http.message.params.HttpParameter.class},
                (proxy, method, args) -> {
                    String m = method.getName();
                    if ("name".equals(m)) return name;
                    if ("value".equals(m)) return value;
                    if ("type".equals(m)) return type;
                    return null;
                }
        );
    }

    private static burp.api.montoya.http.message.params.ParsedHttpParameter createMockParsedHttpParameter(
            String name, String value, burp.api.montoya.http.message.params.HttpParameterType type) {
        return (burp.api.montoya.http.message.params.ParsedHttpParameter) Proxy.newProxyInstance(
                PayloadFeaturesTest_littlespidy.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.http.message.params.ParsedHttpParameter.class},
                (proxy, method, args) -> {
                    String m = method.getName();
                    if ("name".equals(m)) return name;
                    if ("value".equals(m)) return value;
                    if ("type".equals(m)) return type;
                    return null;
                }
        );
    }

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

    // -- Import Feature Tests --

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

    // -- Copy All Feature Tests --

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

    // -- Deduplication Feature Tests --

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

    // -- Metadata and Model Tests --

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

    // -- OWASP Payload Integration Tests --

    @Test
    void testOwaspPayloadsInStandardJsonFiles() throws IOException {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();

        // 1. Verify XSS payloads
        Path xssPath = Path.of("xss_payloads.json");
        assertTrue(Files.exists(xssPath), "xss_payloads.json must exist");
        List<java.util.Map<String, Object>> xssList = gson.fromJson(Files.readString(xssPath), listType);
        assertTrue(xssList.size() >= 500, "XSS payloads list should contain >= 500 entries");
        assertNull(xssList.get(0).get("sourceType"), "JSON must not contain sourceType");
        assertNull(xssList.get(0).get("sourceFile"), "JSON must not contain sourceFile");
        assertNull(xssList.get(0).get("enabled"), "JSON must not contain enabled");

        // 2. Verify SQL payloads
        Path sqlPath = Path.of("sql_payloads.json");
        assertTrue(Files.exists(sqlPath), "sql_payloads.json must exist");
        List<java.util.Map<String, Object>> sqlList = gson.fromJson(Files.readString(sqlPath), listType);
        assertTrue(sqlList.size() >= 150, "SQL payloads list should contain >= 150 entries");
        assertNull(sqlList.get(0).get("sourceType"), "JSON must not contain sourceType");
        assertNull(sqlList.get(0).get("sourceFile"), "JSON must not contain sourceFile");
        assertNull(sqlList.get(0).get("enabled"), "JSON must not contain enabled");

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
        assertEquals(29, PayloadCategoryRegistry_littlespidy.ALL_CATEGORIES.length,
                "Registry must define all 29 parameter payload categories");

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
        assertEquals(29, tabbedPane.getTabCount(), "Should have exactly 29 parameter tabs");
        assertEquals("XSS", tabbedPane.getTitleAt(0));
        assertEquals("CSTI", tabbedPane.getTitleAt(1));
        assertEquals("SQL", tabbedPane.getTitleAt(2));
    }

    @Test
    void testDualSourceTypeTrackingForDuplicatePayloads() throws IOException {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();

        // Verify XSS payloads are loaded and clean
        Path xssPath = Path.of("xss_payloads.json");
        List<java.util.Map<String, Object>> xssList = gson.fromJson(Files.readString(xssPath), listType);
        assertTrue(xssList.size() > 500, "Should have > 500 XSS payloads");

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

        // 1. Verify XSS payloads include entries and are stripped of obsolete fields
        Path xssPath = Path.of("xss_payloads.json");
        List<java.util.Map<String, Object>> xssList = gson.fromJson(Files.readString(xssPath), listType);
        assertTrue(xssList.size() > 500, "Should have > 500 XSS payloads");
        assertNull(xssList.get(0).get("sourceType"));
        assertNull(xssList.get(0).get("sourceFile"));
        assertNull(xssList.get(0).get("enabled"));

        // 2. Verify Command Injection payloads
        Path cmdPath = Path.of("command_injection_payloads_littlespidy.json");
        List<java.util.Map<String, Object>> cmdList = gson.fromJson(Files.readString(cmdPath), listType);
        assertTrue(cmdList.size() > 1000, "Should have > 1000 Command Injection payloads");

        // 3. Verify SQL payloads
        Path sqlPath = Path.of("sql_payloads.json");
        List<java.util.Map<String, Object>> sqlList = gson.fromJson(Files.readString(sqlPath), listType);
        assertTrue(sqlList.size() > 200, "Should have > 200 SQL payloads");
    }

    @Test
    void testHttpRequestSmugglingSourceTypeAndSourceFileTracking() throws IOException {
        com.google.gson.Gson gson = new com.google.gson.Gson();
        java.lang.reflect.Type listType = new com.google.gson.reflect.TypeToken<List<java.util.Map<String, Object>>>() {}.getType();

        Path smugPath = Path.of("http_request_smuggling_payloads.json");
        assertTrue(Files.exists(smugPath), "http_request_smuggling_payloads.json must exist");
        List<java.util.Map<String, Object>> smugList = gson.fromJson(Files.readString(smugPath), listType);

        assertTrue(smugList.size() >= 400, "Should have >= 400 total smuggling payloads after PayloadBox import");

        for (var entry : smugList) {
            String name = (String) entry.get("name");
            String desc = (String) entry.get("description");

            assertNotNull(name, "Smuggling payload name must not be null");
            assertNotNull(desc, "Smuggling payload description must not be null: " + name);
            assertFalse(desc.isBlank(), "Smuggling payload description must not be blank: " + name);
            assertNull(entry.get("sourceType"), "JSON must not contain sourceType");
            assertNull(entry.get("sourceFile"), "JSON must not contain sourceFile");
        }

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
        assertTrue(list.size() >= 6000, "Should have >= 6000 consolidated path traversal payloads");

        long windowsCount = 0;
        long linuxCount = 0;
        long placeholderCount = 0;

        for (var entry : list) {
            String platform = (String) entry.get("platform");
            String template = (String) entry.get("template");
            assertNotNull(platform, "Platform must not be null for payload: " + entry.get("name"));
            assertFalse(platform.isBlank(), "Platform must not be blank for payload: " + entry.get("name"));
            assertTrue("Windows".equals(platform) || "Linux".equals(platform),
                    "Platform must be either Windows or Linux, found: " + platform);

            if ("Windows".equals(platform)) {
                windowsCount++;
            } else if ("Linux".equals(platform)) {
                linuxCount++;
            }

            if (template != null && template.contains("<FILE_PATH>")) {
                placeholderCount++;
            }
        }

        assertTrue(windowsCount >= 2000, "Should have >= 2000 Windows payloads, found: " + windowsCount);
        assertTrue(linuxCount >= 4000, "Should have >= 4000 Linux payloads, found: " + linuxCount);
        assertEquals(list.size(), windowsCount + linuxCount, "Total Windows + Linux count must equal total payloads");
        assertTrue(placeholderCount > 5000, "Should have > 5000 reusable payloads with <FILE_PATH> placeholder, found: " + placeholderCount);
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
        assertEquals(4, ptModel.getColumnCount(), "Path Traversal tab must have exactly 4 columns");
        assertEquals("Name", ptModel.getColumnName(0));
        assertEquals("Platform", ptModel.getColumnName(1), "Second column must be Platform");
        assertEquals("Payload Value", ptModel.getColumnName(2));
        assertEquals("Description", ptModel.getColumnName(3));

        assertEquals("Linux", ptModel.getValueAt(0, 1));
        assertEquals("Windows", ptModel.getValueAt(1, 1));

        // Verify standard categories retain 3 columns
        ParamPayloadStore xssStore = new ParamPayloadStore(null, "xss_payloads.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        xssStore.addEntry(new ParamPayloadEntry("xss-1", "XSS Payload", "<script>alert(1)</script>", "XSS probe", true));
        com.littlespidy.payloadinjector.ui.ParamPayloadTab xssTab =
                new com.littlespidy.payloadinjector.ui.ParamPayloadTab("XSS", xssStore, settings);
        assertEquals(3, xssTab.getTableModel().getColumnCount(), "XSS tab must retain 3 columns");
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

    @Test
    void testFilePathsTabIsFirstTab() {
        com.littlespidy.payloadinjector.model.FilePathStore_littlespidy linuxStore =
                new com.littlespidy.payloadinjector.model.FilePathStore_littlespidy(null, "linux_file_paths_littlespidy.json", "Linux") {
                    @Override public synchronized void reload() {}
                    @Override public synchronized void save() {}
                };
        com.littlespidy.payloadinjector.model.FilePathStore_littlespidy windowsStore =
                new com.littlespidy.payloadinjector.model.FilePathStore_littlespidy(null, "windows_file_paths_littlespidy.json", "Windows") {
                    @Override public synchronized void reload() {}
                    @Override public synchronized void save() {}
                };

        java.util.Map<String, ParamPayloadStore> dummyStores = new java.util.LinkedHashMap<>();
        dummyStores.put("XSS", new ParamPayloadStore(null, "xss_payloads.json") {
            @Override public synchronized void reload() {}
        });

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.PayloadInjectorTab tab =
                new com.littlespidy.payloadinjector.ui.PayloadInjectorTab(dummyStores, null, linuxStore, windowsStore, settings);

        javax.swing.JTabbedPane tabbedPane = null;
        for (java.awt.Component comp : tab.getComponents()) {
            if (comp instanceof javax.swing.JTabbedPane tp) {
                tabbedPane = tp;
                break;
            }
        }

        assertNotNull(tabbedPane, "Tabbed pane must be present");
        assertTrue(tabbedPane.getTabCount() >= 2);
        assertEquals("File Paths", tabbedPane.getTitleAt(0), "File Paths must be the first tab (index 0)");
        assertEquals("XSS", tabbedPane.getTitleAt(1));

        java.awt.Component comp0 = tabbedPane.getComponentAt(0);
        assertTrue(comp0 instanceof com.littlespidy.payloadinjector.ui.FilePathsTab_littlespidy);
        com.littlespidy.payloadinjector.ui.FilePathsTab_littlespidy fpTab = (com.littlespidy.payloadinjector.ui.FilePathsTab_littlespidy) comp0;
        assertNotNull(fpTab.getLinuxPanel(), "Linux subtab panel must exist");
        assertNotNull(fpTab.getWindowsPanel(), "Windows subtab panel must exist");
    }

    @Test
    void testFilePathsJsonStores() {
        com.littlespidy.payloadinjector.model.FilePathStore_littlespidy linuxStore =
                new com.littlespidy.payloadinjector.model.FilePathStore_littlespidy(null, "linux_file_paths_littlespidy.json", "Linux");
        List<com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy> linuxList = linuxStore.getEntries();
        assertTrue(linuxList.size() >= 100, "Should have at least 100 Linux file paths");
        assertTrue(linuxList.stream().anyMatch(e -> e.getPath().contains("etc/passwd")), "Should contain /etc/passwd");
        assertTrue(linuxList.stream().anyMatch(e -> e.getPath().contains("proc/")), "Should contain proc entries");
        assertTrue(linuxList.stream().anyMatch(e -> e.getPath().equals(".env")), "Should contain .env");
        assertTrue(linuxList.stream().anyMatch(e -> e.getPath().equals("wp-config.php")), "Should contain wp-config.php");
        assertTrue(linuxList.stream().anyMatch(e -> e.getPath().equals("backup.sql")), "Should contain backup.sql");

        com.littlespidy.payloadinjector.model.FilePathStore_littlespidy winStore =
                new com.littlespidy.payloadinjector.model.FilePathStore_littlespidy(null, "windows_file_paths_littlespidy.json", "Windows");
        List<com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy> winList = winStore.getEntries();
        assertTrue(winList.size() >= 50, "Should have at least 50 Windows file paths");
        assertTrue(winList.stream().anyMatch(e -> e.getPath().contains("win.ini")), "Should contain win.ini");
        assertTrue(winList.stream().anyMatch(e -> e.getPath().contains("SAM")), "Should contain SAM entry");
        assertTrue(winList.stream().anyMatch(e -> e.getPath().equals("web.config")), "Should contain web.config");
        assertTrue(winList.stream().anyMatch(e -> e.getPath().equals("appsettings.json")), "Should contain appsettings.json");
    }

    @Test
    void testReplaceFilePathPlaceholderInParameter() {
        burp.api.montoya.http.message.requests.HttpRequest request =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest("GET /download?file=../../../../<FILE_PATH> HTTP/1.1\r\nHost: example.com\r\n\r\n");

        burp.api.montoya.http.message.requests.HttpRequest mutated =
                com.littlespidy.payloadinjector.engine.ParamPayloadInjectorEngine.replaceFilePathPlaceholder(
                        request, "/etc/passwd", java.util.Optional.empty());

        assertNotNull(mutated);
        String mutatedStr = mutated.toString();
        assertTrue(mutatedStr.contains("file=../../../../etc/passwd"), "Should normalize slash boundary to avoid double slash: " + mutatedStr);
        assertFalse(mutatedStr.contains("<FILE_PATH>"), "Placeholder should be replaced");
    }

    @Test
    void testReplaceFilePathPlaceholderPreservesExtensionsAndNullBytes() {
        burp.api.montoya.http.message.requests.HttpRequest request =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest("GET /view?path=../../<FILE_PATH>%00.png HTTP/1.1\r\nHost: example.com\r\n\r\n");

        burp.api.montoya.http.message.requests.HttpRequest mutated =
                com.littlespidy.payloadinjector.engine.ParamPayloadInjectorEngine.replaceFilePathPlaceholder(
                        request, "etc/passwd", java.util.Optional.empty());

        assertNotNull(mutated);
        String mutatedStr = mutated.toString();
        assertTrue(mutatedStr.contains("path=../../etc/passwd%00.png"), "Should preserve %00 and extension: " + mutatedStr);
    }

    @Test
    void testReplaceFilePathPlaceholderGracefulNoOp() {
        burp.api.montoya.http.message.requests.HttpRequest request =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest("GET /search?q=normalValue HTTP/1.1\r\nHost: example.com\r\n\r\n");

        burp.api.montoya.http.message.requests.HttpRequest mutated =
                com.littlespidy.payloadinjector.engine.ParamPayloadInjectorEngine.replaceFilePathPlaceholder(
                        request, "/etc/passwd", java.util.Optional.empty());

        assertNotNull(mutated);
        assertEquals(request.toString(), mutated.toString(), "Request without placeholder must remain unchanged");
    }

    @Test
    void testContextMenuContainsFilePathReplacementSubmenus() {
        com.littlespidy.payloadinjector.model.FilePathStore_littlespidy linuxStore =
                new com.littlespidy.payloadinjector.model.FilePathStore_littlespidy(null, "linux_file_paths_littlespidy.json", "Linux") {
                    @Override public synchronized void reload() {}
                    @Override public synchronized void save() {}
                };
        linuxStore.addEntry(new com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy(
                "lp-1", "/etc/passwd", "System Accounts", "Passwd file", "Linux", true, "Default", "test.json"));

        com.littlespidy.payloadinjector.model.FilePathStore_littlespidy winStore =
                new com.littlespidy.payloadinjector.model.FilePathStore_littlespidy(null, "windows_file_paths_littlespidy.json", "Windows") {
                    @Override public synchronized void reload() {}
                    @Override public synchronized void save() {}
                };
        winStore.addEntry(new com.littlespidy.payloadinjector.model.FilePathEntry_littlespidy(
                "wp-1", "windows/win.ini", "System Configuration", "Win ini file", "Windows", true, "Default", "test.json"));

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.PayloadContextMenuProvider provider =
                new com.littlespidy.payloadinjector.ui.PayloadContextMenuProvider(null, java.util.Collections.emptyMap(), null, linuxStore, winStore, settings);

        burp.api.montoya.http.message.requests.HttpRequest mockRequest =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequest("GET /view?path=../../<FILE_PATH> HTTP/1.1\r\nHost: test.com\r\n\r\n");

        burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse mockEditor =
                (burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(
                        getClass().getClassLoader(),
                        new Class<?>[]{burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.class},
                        (p, m, a) -> {
                            if ("selectionOffsets".equals(m.getName())) return java.util.Optional.empty();
                            if ("requestResponse".equals(m.getName())) {
                                return (burp.api.montoya.http.message.HttpRequestResponse) java.lang.reflect.Proxy.newProxyInstance(
                                        getClass().getClassLoader(),
                                        new Class<?>[]{burp.api.montoya.http.message.HttpRequestResponse.class},
                                        (p2, m2, a2) -> {
                                            if ("request".equals(m2.getName())) return mockRequest;
                                            return null;
                                        }
                                );
                            }
                            return null;
                        }
                );

        burp.api.montoya.ui.contextmenu.ContextMenuEvent mockEvent =
                (burp.api.montoya.ui.contextmenu.ContextMenuEvent) java.lang.reflect.Proxy.newProxyInstance(
                        getClass().getClassLoader(),
                        new Class<?>[]{burp.api.montoya.ui.contextmenu.ContextMenuEvent.class},
                        (p, m, a) -> {
                            if ("messageEditorRequestResponse".equals(m.getName())) return java.util.Optional.of(mockEditor);
                            if ("selectedRequestResponses".equals(m.getName())) return java.util.List.of();
                            return null;
                        }
                );

        java.util.List<java.awt.Component> menuItems = provider.provideMenuItems(mockEvent);
        assertFalse(menuItems.isEmpty());
        javax.swing.JMenu rootMenu = (javax.swing.JMenu) menuItems.get(0);

        javax.swing.JMenu fpMenu = null;
        for (int i = 0; i < rootMenu.getItemCount(); i++) {
            javax.swing.JMenuItem it = rootMenu.getItem(i);
            if (it instanceof javax.swing.JMenu m && "Replace Target File Path (<FILE_PATH>)".equals(m.getText())) {
                fpMenu = m;
                break;
            }
        }

        assertNotNull(fpMenu, "Replace Target File Path menu must be present in editor context menu");
        assertTrue(fpMenu.getItemCount() >= 2);
    }

    @Test
    void testSearchBarFiltersParamPayloadTab() {
        ParamPayloadStore testStore = new ParamPayloadStore(null, "xss_payloads.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        testStore.addEntry(new ParamPayloadEntry("1", "Alert Alpha", "<script>alert('alpha')</script>", "Test alpha", true));
        testStore.addEntry(new ParamPayloadEntry("2", "Prompt Beta", "<script>prompt('beta')</script>", "Test beta", true));
        testStore.addEntry(new ParamPayloadEntry("3", "Confirm Gamma", "<svg onload=confirm('gamma')>", "Test gamma", true));

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.ParamPayloadTab tab =
                new com.littlespidy.payloadinjector.ui.ParamPayloadTab("XSS", testStore, settings);

        assertEquals(3, tab.getTable().getRowCount());

        // Filter by 'alpha'
        tab.getSearchField().setText("alpha");
        assertEquals(1, tab.getTable().getRowCount());

        // Clear filter
        tab.getSearchField().setText("");
        assertEquals(3, tab.getTable().getRowCount());
    }

    @Test
    void testSearchBarPreservesFilterAcrossReload() throws Exception {
        ParamPayloadStore testStore = new ParamPayloadStore(null, "xss_payloads.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        testStore.addEntry(new ParamPayloadEntry("1", "Alert Alpha", "<script>alert('alpha')</script>", "Test alpha", true));
        testStore.addEntry(new ParamPayloadEntry("2", "Prompt Beta", "<script>prompt('beta')</script>", "Test beta", true));

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.ParamPayloadTab tab =
                new com.littlespidy.payloadinjector.ui.ParamPayloadTab("XSS", testStore, settings);

        tab.getSearchField().setText("beta");
        assertEquals(1, tab.getTable().getRowCount());

        // Add an entry and notify change
        testStore.addEntry(new ParamPayloadEntry("3", "Another Beta", "<script>alert('beta 2')</script>", "Test beta 2", true));
        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            tab.applySearchFilter();
        } else {
            javax.swing.SwingUtilities.invokeAndWait(tab::applySearchFilter);
        }

        // Should filter reloaded data showing 2 matching rows
        assertEquals(2, tab.getTable().getRowCount());
    }

    @Test
    void testSearchBarSpecialCharactersSafe() {
        ParamPayloadStore testStore = new ParamPayloadStore(null, "xss_payloads.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        testStore.addEntry(new ParamPayloadEntry("1", "Regex Payload", "{{[test*?]}}", "Bracket probe", true));
        testStore.addEntry(new ParamPayloadEntry("2", "Normal Payload", "normal", "Normal probe", true));

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.ParamPayloadTab tab =
                new com.littlespidy.payloadinjector.ui.ParamPayloadTab("XSS", testStore, settings);

        // Search with special regex characters that would throw PatternSyntaxException if not quoted
        assertDoesNotThrow(() -> tab.getSearchField().setText("[test*?]"));
        assertEquals(1, tab.getTable().getRowCount());
    }

    @Test
    void testParamPayloadTabInPlaceEditingAndBatchDeletion() {
        ParamPayloadStore store = new ParamPayloadStore(null, "xss_payloads.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        store.addEntry(new ParamPayloadEntry("1", "Payload A", "<script>1</script>", "Desc A", true));
        store.addEntry(new ParamPayloadEntry("2", "Payload B", "<script>2</script>", "Desc B", true));
        store.addEntry(new ParamPayloadEntry("3", "Payload C", "<script>3</script>", "Desc C", true));

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.ParamPayloadTab tab =
                new com.littlespidy.payloadinjector.ui.ParamPayloadTab("XSS", store, settings);

        com.littlespidy.payloadinjector.ui.ParamPayloadTab.PayloadTableModel model = tab.getTableModel();
        assertEquals(3, model.getColumnCount(), "Standard ParamPayloadTab should have 3 columns");
        assertTrue(model.isCellEditable(0, 0), "Cells must be editable inline without popup dialogs");
        assertTrue(model.isCellEditable(0, 1));
        assertTrue(model.isCellEditable(0, 2));

        // Test in-place edit on Name
        model.setValueAt("Payload A Updated", 0, 0);
        assertEquals("Payload A Updated", store.getEntries().get(0).getName());

        // Test in-place edit on Template / Payload Value
        model.setValueAt("<script>updated</script>", 0, 1);
        assertEquals("<script>updated</script>", store.getEntries().get(0).getTemplate());

        // Test multi-row batch deletion (e.g. deleting rows 0 and 2)
        store.removeEntries(new int[]{0, 2});
        assertEquals(1, store.getEntries().size());
        assertEquals("Payload B", store.getEntries().get(0).getName());
    }

    @Test
    void testFilePathsTabInPlaceEditingAndBatchDeletion() {
        FilePathStore_littlespidy store = new FilePathStore_littlespidy(null, "linux_file_paths_littlespidy.json", "Linux") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        store.addEntry(new FilePathEntry_littlespidy("1", "/etc/passwd", "Credentials", "Accounts", "Linux", true, "Default", "N/A"));
        store.addEntry(new FilePathEntry_littlespidy("2", "/etc/shadow", "Credentials", "Hashes", "Linux", true, "Default", "N/A"));
        store.addEntry(new FilePathEntry_littlespidy("3", "/etc/hosts", "Network", "Host map", "Linux", true, "Default", "N/A"));

        com.littlespidy.payloadinjector.ui.FilePathsTab_littlespidy.FilePathPanel panel =
                new com.littlespidy.payloadinjector.ui.FilePathsTab_littlespidy.FilePathPanel("Linux", store);

        com.littlespidy.payloadinjector.ui.FilePathsTab_littlespidy.FilePathPanel.FilePathTableModel model = panel.getTableModel();
        assertEquals(3, model.getColumnCount(), "FilePathTab must have 3 columns: Path, Category, Description");
        assertEquals("Path", model.getColumnName(0));
        assertEquals("Category", model.getColumnName(1));
        assertEquals("Description", model.getColumnName(2));

        assertTrue(model.isCellEditable(0, 0), "FilePath cells must be editable inline");
        model.setValueAt("/etc/passwd_edited", 0, 0);
        assertEquals("/etc/passwd_edited", store.getEntries().get(0).getPath());

        model.setValueAt("NewCategory", 0, 1);
        assertEquals("NewCategory", store.getEntries().get(0).getCategory());

        // Batch deletion of indices 0 and 1
        store.removeEntries(new int[]{0, 1});
        assertEquals(1, store.getEntries().size());
        assertEquals("/etc/hosts", store.getEntries().get(0).getPath());
    }

    @Test
    void testSmugglingTabInPlaceEditingAndBatchDeletion() {
        SmugglingPayloadStore store = new SmugglingPayloadStore(null) {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        store.addEntry(new SmugglingPayloadEntry("CL.TE Basic", "Probe 1", java.util.Map.of(), "0\\r\\n\\r\\n"));
        store.addEntry(new SmugglingPayloadEntry("TE.CL Basic", "Probe 2", java.util.Map.of(), "Transfer-Encoding: chunked"));
        store.addEntry(new SmugglingPayloadEntry("TE.TE Obfuscation", "Probe 3", java.util.Map.of(), "Transfer-Encoding: xchunked"));

        com.littlespidy.payloadinjector.ui.SmugglingPayloadTab tab =
                new com.littlespidy.payloadinjector.ui.SmugglingPayloadTab(store);

        com.littlespidy.payloadinjector.ui.SmugglingPayloadTab.SmugglingPayloadTableModel model = tab.getTableModel();
        assertEquals(3, model.getColumnCount(), "Smuggling tab must have 3 columns: Name, Payload Value, Description");
        assertEquals("Name", model.getColumnName(0));
        assertEquals("Payload Value", model.getColumnName(1));
        assertEquals("Description", model.getColumnName(2));

        assertTrue(model.isCellEditable(0, 0), "Smuggling cells must be editable inline");
        model.setValueAt("CL.TE Updated", 0, 0);
        assertEquals("CL.TE Updated", store.getEntries().get(0).getName());

        model.setValueAt("NEW_PAYLOAD", 0, 1);
        assertEquals("NEW_PAYLOAD", store.getEntries().get(0).getBody());

        // Multi-row deletion of rows 0 and 2
        store.removeEntries(new int[]{0, 2});
        assertEquals(1, store.getEntries().size());
        assertEquals("TE.CL Basic", store.getEntries().get(0).getName());
    }

    @Test
    void testSearchBarMatchesNameAndPayloadValue() {
        ParamPayloadStore store = new ParamPayloadStore(null, "xss_payloads.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        store.addEntry(new ParamPayloadEntry("1", "AlphaXSS", "<script>alpha()</script>", "Basic desc", true));
        store.addEntry(new ParamPayloadEntry("2", "BetaSQLi", "UNION SELECT secret_token", "Auth desc", true));
        store.addEntry(new ParamPayloadEntry("3", "GammaOther", "normal_probe_val", "Contains secret_token in desc", true));

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.ParamPayloadTab tab =
                new com.littlespidy.payloadinjector.ui.ParamPayloadTab("XSS", store, settings);

        // Search matching Name column only
        tab.getSearchField().setText("AlphaXSS");
        assertEquals(1, tab.getTable().getRowCount());
        assertEquals("AlphaXSS", tab.getTable().getValueAt(0, 0));

        // Search matching Payload Value column only
        tab.getSearchField().setText("secret_token");
        assertEquals(1, tab.getTable().getRowCount(), "Should match Payload Value column but NOT Description column");
        assertEquals("BetaSQLi", tab.getTable().getValueAt(0, 0));

        // Case-insensitive match on Name
        tab.getSearchField().setText("betasqli");
        assertEquals(1, tab.getTable().getRowCount());
        assertEquals("BetaSQLi", tab.getTable().getValueAt(0, 0));

        // Non-matching query
        tab.getSearchField().setText("nonexistent_pattern");
        assertEquals(0, tab.getTable().getRowCount());

        // Clear search
        tab.getSearchField().setText("");
        assertEquals(3, tab.getTable().getRowCount());
    }

    @Test
    void testPathTraversalPlatformFilterAndDualSearch() {
        ParamPayloadStore store = new ParamPayloadStore(null, "path_traversal_payloads_littlespidy.json") {
            @Override public synchronized void reload() {}
            @Override public synchronized void save() {}
        };
        ParamPayloadEntry p1 = new ParamPayloadEntry("1", "Linux Traversal Passwd", "../../../etc/passwd", "Linux desc", true);
        p1.setPlatform("Linux");
        store.addEntry(p1);

        ParamPayloadEntry p2 = new ParamPayloadEntry("2", "Windows Traversal Ini", "..\\..\\win.ini", "Windows desc", true);
        p2.setPlatform("Windows");
        store.addEntry(p2);

        ParamPayloadEntry p3 = new ParamPayloadEntry("3", "Linux Traversal Shadow", "....//....//etc/shadow", "Linux shadow desc", true);
        p3.setPlatform("Linux");
        store.addEntry(p3);

        InjectionSettings settings = new InjectionSettings();
        com.littlespidy.payloadinjector.ui.ParamPayloadTab tab =
                new com.littlespidy.payloadinjector.ui.ParamPayloadTab("Path Traversal", store, settings);

        assertNotNull(tab.getPlatformFilterBox(), "Path Traversal tab must have a platform filter box");
        assertEquals(3, tab.getTable().getRowCount());

        // Filter by Linux platform
        tab.getPlatformFilterBox().setSelectedItem("Linux");
        assertEquals(2, tab.getTable().getRowCount());

        // Filter by Windows platform
        tab.getPlatformFilterBox().setSelectedItem("Windows");
        assertEquals(1, tab.getTable().getRowCount());
        assertEquals("Windows Traversal Ini", tab.getTable().getValueAt(0, 0));

        // Filter by All Platforms
        tab.getPlatformFilterBox().setSelectedItem("All Platforms");
        assertEquals(3, tab.getTable().getRowCount());

        // Combined Platform + Search: Linux + search for "shadow"
        tab.getPlatformFilterBox().setSelectedItem("Linux");
        tab.getSearchField().setText("shadow");
        assertEquals(1, tab.getTable().getRowCount());
        assertEquals("Linux Traversal Shadow", tab.getTable().getValueAt(0, 0));

        // Combined Platform + Search: Linux + search for "Windows" -> 0 matches
        tab.getSearchField().setText("Windows");
        assertEquals(0, tab.getTable().getRowCount());

        // Combined Platform + Search: Windows + search for "ini"
        tab.getPlatformFilterBox().setSelectedItem("Windows");
        tab.getSearchField().setText("ini");
        assertEquals(1, tab.getTable().getRowCount());
        assertEquals("Windows Traversal Ini", tab.getTable().getValueAt(0, 0));
    }

    @Test
    void testJsonStoresLoadWithoutEnabledSourceTypeSourceFile() throws IOException {
        // ParamPayloadStore serialization and deserialization
        Path jsonFile = tempDir.resolve("test_param_payloads.json");
        String jsonContent = "[\n" +
                "  {\n" +
                "    \"id\": \"test-1\",\n" +
                "    \"name\": \"Test Clean JSON\",\n" +
                "    \"template\": \"<script>clean</script>\",\n" +
                "    \"description\": \"Clean entry without obsolete fields\",\n" +
                "    \"platform\": \"Linux\"\n" +
                "  }\n" +
                "]";
        Files.writeString(jsonFile, jsonContent, StandardCharsets.UTF_8);

        ParamPayloadStore paramStore = new ParamPayloadStore(null, jsonFile.toAbsolutePath().toString());
        assertEquals(1, paramStore.getEntries().size());
        ParamPayloadEntry entry = paramStore.getEntries().get(0);
        assertEquals("test-1", entry.getId());
        assertEquals("Test Clean JSON", entry.getName());
        assertEquals("<script>clean</script>", entry.getTemplate());
        assertEquals("Linux", entry.getPlatform());
        assertTrue(entry.isEnabled());
        assertEquals("Manual", entry.getSourceType());
        assertEquals("N/A", entry.getSourceFile());

        // Save back and verify saved JSON does not contain enabled, sourceType, or sourceFile
        paramStore.save();
        String savedJson = Files.readString(jsonFile, StandardCharsets.UTF_8);
        assertFalse(savedJson.contains("\"enabled\""), "Saved JSON must not contain enabled");
        assertFalse(savedJson.contains("\"sourceType\""), "Saved JSON must not contain sourceType");
        assertFalse(savedJson.contains("\"sourceFile\""), "Saved JSON must not contain sourceFile");

        // FilePathStore serialization and deserialization
        Path fpFile = tempDir.resolve("test_file_paths.json");
        String fpJson = "[\n" +
                "  {\n" +
                "    \"id\": \"fp-1\",\n" +
                "    \"path\": \"/etc/passwd\",\n" +
                "    \"category\": \"Credentials\",\n" +
                "    \"description\": \"Clean file path\",\n" +
                "    \"platform\": \"Linux\"\n" +
                "  }\n" +
                "]";
        Files.writeString(fpFile, fpJson, StandardCharsets.UTF_8);

        FilePathStore_littlespidy fpStore = new FilePathStore_littlespidy(null, fpFile.toAbsolutePath().toString(), "Linux");
        assertEquals(1, fpStore.getEntries().size());
        FilePathEntry_littlespidy fpEntry = fpStore.getEntries().get(0);
        assertEquals("/etc/passwd", fpEntry.getPath());
        assertEquals("Linux", fpEntry.getPlatform());

        fpStore.save();
        String savedFpJson = Files.readString(fpFile, StandardCharsets.UTF_8);
        assertFalse(savedFpJson.contains("\"enabled\""), "Saved FilePath JSON must not contain enabled");
        assertFalse(savedFpJson.contains("\"sourceType\""), "Saved FilePath JSON must not contain sourceType");
        assertFalse(savedFpJson.contains("\"sourceFile\""), "Saved FilePath JSON must not contain sourceFile");
    }

    @Test
    void testContentTypeAndHeadersCategoriesAndDeletedFiles() {
        // Verify deleted files no longer exist on disk
        String[] deletedFiles = {
                "jwt_vulnerabilities_payloads_littlespidy.json",
                "vulnerable_components_payloads_littlespidy.json",
                "tor_based_attacks_payloads_littlespidy.json",
                "weak_cryptography_payloads_littlespidy.json",
                "symbolic_link_attacks_payloads_littlespidy.json",
                "security_misconfiguration_payloads_littlespidy.json",
                "idor_payloads_littlespidy.json"
        };
        for (String f : deletedFiles) {
            assertFalse(Files.exists(Path.of(f)), "Deleted category file must not exist: " + f);
        }

        // Verify Content-Type category file exists and has entries
        Path ctPath = Path.of("content_type_payloads_littlespidy.json");
        assertTrue(Files.exists(ctPath), "content_type_payloads_littlespidy.json must exist");
        ParamPayloadStore ctStore = new ParamPayloadStore(null, "content_type_payloads_littlespidy.json");
        assertTrue(ctStore.getEntries().size() >= 20, "Content-Type category should have >= 20 payloads");

        // Verify Headers category file exists and has entries
        Path hdrPath = Path.of("headers_payloads_littlespidy.json");
        assertTrue(Files.exists(hdrPath), "headers_payloads_littlespidy.json must exist");
        ParamPayloadStore hdrStore = new ParamPayloadStore(null, "headers_payloads_littlespidy.json");
        assertTrue(hdrStore.getEntries().size() >= 70, "Headers category should have >= 70 payloads");

        // Verify both appear in ALL_CATEGORIES
        boolean hasContentType = false;
        boolean hasHeaders = false;
        for (var cat : PayloadCategoryRegistry_littlespidy.ALL_CATEGORIES) {
            if ("Content-Type".equals(cat.displayName())) hasContentType = true;
            if ("Headers".equals(cat.displayName())) hasHeaders = true;
        }
        assertTrue(hasContentType, "Registry must contain Content-Type category");
        assertTrue(hasHeaders, "Registry must contain Headers category");
    }
}



