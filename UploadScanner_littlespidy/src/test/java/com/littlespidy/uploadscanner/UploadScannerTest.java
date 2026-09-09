package com.littlespidy.uploadscanner;

import burp.api.montoya.core.Marker;
import com.littlespidy.uploadscanner.engine.MarkerHighlighter;
import com.littlespidy.uploadscanner.engine.ReDownloaderEngine;
import com.littlespidy.uploadscanner.engine.UploadPayloadGenerator;
import com.littlespidy.uploadscanner.model.*;
import com.littlespidy.uploadscanner.ui.UploadLogTableModel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Unit tests covering ReDownloader extraction, offset calculation,
 * payload generation, and log table filtering.
 *
 * @author littlespidy
 */
class UploadScannerTest {

    @Test
    @DisplayName("MarkerHighlighter: Extract text and accurate character offsets between markers")
    void testMarkerHighlighterOffsets() {
        String response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\",\"file_url\":\"/uploads/avatar_123.png\",\"size\":1024}";
        String startMarker = "\"file_url\":\"";
        String endMarker = "\"";

        MarkerHighlighter.ExtractionResult result =
                MarkerHighlighter.extractBetweenMarkers(response, startMarker, endMarker);

        assertTrue(result.isFound(), "Expected markers to be found");
        assertEquals("/uploads/avatar_123.png", result.getExtractedText());

        // Verify offsets
        int expectedStart = response.indexOf("/uploads/avatar_123.png");
        int expectedEnd = expectedStart + "/uploads/avatar_123.png".length();
        assertEquals(expectedStart, result.getContentStartOffset());
        assertEquals(expectedEnd, result.getContentEndOffset());
    }

    @Test
    @DisplayName("MarkerHighlighter: Return notFound when markers are missing")
    void testMarkerHighlighterMissing() {
        String response = "404 Not Found";
        MarkerHighlighter.ExtractionResult result =
                MarkerHighlighter.extractBetweenMarkers(response, "{\"url\":\"", "\"}");

        assertFalse(result.isFound());
        assertEquals("", result.getExtractedText());
        assertTrue(result.toMarkers().isEmpty());
    }

    @Test
    @DisplayName("ReDownloaderEngine: Placeholder resolution and URL normalization")
    void testReDownloaderPlaceholderAndNormalization() {
        ReDownloaderConfig config = new ReDownloaderConfig();
        config.setStartMarker("\"url\":\"");
        config.setEndMarker("\"");
        config.setUrlPrefix("https://cdn.example.com");
        config.setUrlSuffix("?view=raw");
        config.setReplaceBackslash(true);

        ReDownloaderEngine engine = new ReDownloaderEngine(null, config);

        // Test placeholder resolution
        String template = "/files/${FILENAME_NO_EXT}/${FILENAME}?orig=${ORIG_EXT}";
        String resolved = engine.resolvePlaceholders(template, "profile.image.jpeg");
        assertEquals("/files/profile.image/profile.image.jpeg?orig=jpeg", resolved);

        // Test response parsing with escaped slashes
        String jsonResponse = "{\"status\":200,\"url\":\"\\/static\\/uploads\\/test.png\"}";
        MarkerHighlighter.ExtractionResult parsed = engine.parseDownloadUrl(jsonResponse, "test.png");

        assertTrue(parsed.isFound());
        assertEquals("https://cdn.example.com/static/uploads/test.png?view=raw", parsed.getExtractedText());
    }

    @Test
    @DisplayName("ReDownloaderEngine: Static URL fallback")
    void testReDownloaderStaticUrl() {
        ReDownloaderConfig config = new ReDownloaderConfig();
        config.setStaticUrl("/storage/${FILENAME}");

        ReDownloaderEngine engine = new ReDownloaderEngine(null, config);
        MarkerHighlighter.ExtractionResult result = engine.parseDownloadUrl("", "my_avatar.gif");

        assertTrue(result.isFound());
        assertEquals("/storage/my_avatar.gif", result.getExtractedText());
    }

    @Test
    @DisplayName("UploadPayloadGenerator: Generate payloads across all enabled attack vectors")
    void testPayloadGenerator() {
        UploadScannerConfig config = new UploadScannerConfig();
        config.setTestWebShells(true);
        config.setTestPolyglots(true);
        config.setTestPathTraversal(true);
        config.setTestExtensionBypasses(true);
        config.setTestSvgXss(true);
        config.setTestEicar(true);

        List<PayloadDefinition> payloads = UploadPayloadGenerator.generatePayloads(config, "avatar.png");
        assertFalse(payloads.isEmpty());
        assertTrue(payloads.size() >= 10);

        // Verify GIF89a Polyglot magic bytes
        boolean foundGif = false;
        boolean foundPhp = false;
        boolean foundSvg = false;
        boolean foundEicar = false;

        for (PayloadDefinition p : payloads) {
            if (p.getName().contains("GIF89a Polyglot")) {
                foundGif = true;
                assertTrue(new String(p.getContent()).startsWith("GIF89a"));
            }
            if (p.getName().contains("PHP Info Shell")) {
                foundPhp = true;
                assertEquals("application/x-php", p.getContentType());
            }
            if (p.getName().contains("SVG Stored XSS")) {
                foundSvg = true;
                assertEquals("image/svg+xml", p.getContentType());
            }
            if (p.getName().contains("EICAR")) {
                foundEicar = true;
                assertTrue(new String(p.getContent()).contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"));
            }
        }

        assertTrue(foundGif, "GIF Polyglot should be present");
        assertTrue(foundPhp, "PHP Shell should be present");
        assertTrue(foundSvg, "SVG XSS should be present");
        assertTrue(foundEicar, "EICAR check should be present");
    }

    @Test
    @DisplayName("UploadLogTableModel: Filtering by Stage, Status, Method, and Search Query")
    void testLogTableModelFiltering() {
        UploadLogTableModel model = new UploadLogTableModel();

        UploadEntry e1 = new UploadEntry(1, StageType.UPLOAD, "POST", (short) 200, "upload_test.php",
                512, "https://example.com/api/upload", null, "", null, null);
        UploadEntry e2 = new UploadEntry(2, StageType.PREFLIGHT, "GET", (short) 302, "Preflight: test.php",
                128, "https://example.com/gallery", null, "", null, null);
        UploadEntry e3 = new UploadEntry(3, StageType.REDOWNLOAD, "GET", (short) 404, "ReDownload: test.php",
                64, "https://example.com/uploads/test.php", null, "/uploads/test.php", null, null);
        UploadEntry e4 = new UploadEntry(4, StageType.REDOWNLOAD, "GET", (short) 200, "ReDownload: vector.svg",
                1024, "https://example.com/uploads/vector.svg", null, "/uploads/vector.svg", null, null);

        model.addEntry(e1);
        model.addEntry(e2);
        model.addEntry(e3);
        model.addEntry(e4);

        assertEquals(4, model.getRowCount());

        // 1. Filter by Stage: ReDownload only
        model.applyFilters(Set.of("ReDownload"), null, null, "");
        assertEquals(2, model.getRowCount());

        // 2. Filter by Status: 2xx only
        model.applyFilters(null, Set.of("2xx"), null, "");
        assertEquals(2, model.getRowCount()); // e1 (Upload 200) and e4 (ReDownload 200)

        // 3. Filter by Method: POST only
        model.applyFilters(null, null, Set.of("POST"), "");
        assertEquals(1, model.getRowCount());
        assertEquals("POST", model.getValueAt(0, 2));

        // 4. Filter by Search Query
        model.applyFilters(null, null, null, "vector.svg");
        assertEquals(1, model.getRowCount());
        assertEquals("ReDownload: vector.svg", model.getValueAt(0, 4));

        // 5. Clear Log
        model.clear();
        assertEquals(0, model.getRowCount());
    }
}
