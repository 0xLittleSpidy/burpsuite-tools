package com.littlespidy.uploadscanner;

import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.uploadscanner.engine.MarkerHighlighter;
import com.littlespidy.uploadscanner.engine.ReDownloaderEngine;
import com.littlespidy.uploadscanner.engine.UploadPayloadGenerator;
import com.littlespidy.uploadscanner.engine.UploadScanExecutor;
import com.littlespidy.uploadscanner.model.*;
import com.littlespidy.uploadscanner.ui.UploadLogTableModel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

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

    @Test
    @DisplayName("ReDownloaderEngine: Auto-detect download URL from JSON response and unescape slashes")
    void testAutoDetectDownloadUrlJson() {
        ReDownloaderConfig config = new ReDownloaderConfig();
        config.setReplaceBackslash(true);
        ReDownloaderEngine engine = new ReDownloaderEngine(null, config);

        String jsonResp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                "{\"status\":\"success\",\"file_path\":\"\\/media\\/uploads\\/my_photo.jpg\",\"size\":4096}";

        ReDownloaderEngine.DetectionResult result = engine.autoDetectDownloadUrl(jsonResp, "upload_probe.tmp");
        assertTrue(result.isFound(), "URL should be auto-detected from JSON response");
        assertEquals("/media/uploads/my_photo.jpg", result.getDetectedUrl());
        assertTrue(result.getReason().contains("file_path"));
    }

    @Test
    @DisplayName("ReDownloaderEngine: Auto-detect download URL from HTML media and link tags")
    void testAutoDetectDownloadUrlHtml() {
        ReDownloaderConfig config = new ReDownloaderConfig();
        ReDownloaderEngine engine = new ReDownloaderEngine(null, config);

        String htmlResp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
                "<html><body><h1>User Profile</h1><img src=\"/static/avatars/user_101.png\"></body></html>";

        ReDownloaderEngine.DetectionResult result = engine.autoDetectDownloadUrl(htmlResp, "user_101.png");
        assertTrue(result.isFound(), "URL should be auto-detected from <img> tag");
        assertEquals("/static/avatars/user_101.png", result.getDetectedUrl());
    }

    @Test
    @DisplayName("ReDownloaderEngine: Auto-detect download URL from HTTP Location redirect header")
    void testAutoDetectDownloadUrlLocation() {
        ReDownloaderConfig config = new ReDownloaderConfig();
        ReDownloaderEngine engine = new ReDownloaderEngine(null, config);

        String redirectResp = "HTTP/1.1 302 Found\r\nLocation: /cdn/files/document_v2.pdf\r\nContent-Length: 0\r\n\r\n";

        ReDownloaderEngine.DetectionResult result = engine.autoDetectDownloadUrl(redirectResp, "document_v2.pdf");
        assertTrue(result.isFound(), "URL should be detected from Location header");
        assertEquals("/cdn/files/document_v2.pdf", result.getDetectedUrl());
        assertTrue(result.getReason().contains("Location"));
    }

    @Test
    @DisplayName("ReDownloaderEngine: Auto-detect download URL from uploaded filename reflection")
    void testAutoDetectDownloadUrlFilenameReflection() {
        ReDownloaderConfig config = new ReDownloaderConfig();
        ReDownloaderEngine engine = new ReDownloaderEngine(null, config);

        String bodyResp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" +
                "Uploaded successfully! Path: 'https://cloud-storage.example.com/blobs/custom_asset_99.gif' generated.";

        ReDownloaderEngine.DetectionResult result = engine.autoDetectDownloadUrl(bodyResp, "custom_asset_99.gif");
        assertTrue(result.isFound(), "URL should be detected from filename reflection");
        assertEquals("https://cloud-storage.example.com/blobs/custom_asset_99.gif", result.getDetectedUrl());
    }

    @Test
    @DisplayName("ReDownloaderEngine: 1-Click Marker derivation from response text selection")
    void testDeriveMarkersFromSelection() {
        ReDownloaderConfig config = new ReDownloaderConfig();
        ReDownloaderEngine engine = new ReDownloaderEngine(null, config);

        String fullText = "{\"status\":200,\"download_url\":\"/storage/user_files/report.pdf\"}";
        int selStart = fullText.indexOf("/storage/user_files/report.pdf");
        int selEnd = selStart + "/storage/user_files/report.pdf".length();

        ReDownloaderEngine.DetectionResult result = engine.deriveMarkersFromSelection(fullText, selStart, selEnd);
        assertTrue(result.isFound(), "Selection derivation should succeed");
        assertEquals("/storage/user_files/report.pdf", result.getDetectedUrl());
        assertFalse(result.getSuggestedStartMarker().isEmpty());
        assertFalse(result.getSuggestedEndMarker().isEmpty());

        // Test with invalid offset bounds
        ReDownloaderEngine.DetectionResult invalidResult = engine.deriveMarkersFromSelection(fullText, 50, 10);
        assertFalse(invalidResult.isFound());
    }

    @Test
    @DisplayName("Archive Generators: Zip Slip archive format integrity and traversal entry")
    void testZipSlipArchiveIntegrity() throws IOException {
        byte[] zipBytes = UploadPayloadGenerator.createZipSlipArchive("test_token_123");
        assertNotNull(zipBytes);
        assertTrue(zipBytes.length > 0);

        boolean foundTraversalEntry = false;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().contains("../../../../traversal_shell.php")) {
                    foundTraversalEntry = true;
                    byte[] content = zis.readAllBytes();
                    assertTrue(new String(content).contains("test_token_123"));
                }
                zis.closeEntry();
            }
        }
        assertTrue(foundTraversalEntry, "Zip Slip archive must contain directory traversal path");
    }

    @Test
    @DisplayName("Archive Generators: Office DOCX XXE ZIP package integrity")
    void testOfficeDocxXxeIntegrity() throws IOException {
        String collabDomain = "target-xxe.oob.burpcollaborator.net";
        byte[] docxBytes = UploadPayloadGenerator.createOfficeDocxXxe(collabDomain);
        assertNotNull(docxBytes);
        assertTrue(docxBytes.length > 0);

        Set<String> entriesFound = new HashSet<>();
        boolean xxeFound = false;

        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(docxBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                entriesFound.add(entry.getName());
                if ("word/document.xml".equals(entry.getName())) {
                    byte[] content = zis.readAllBytes();
                    String xml = new String(content);
                    if (xml.contains(collabDomain) && xml.contains("<!DOCTYPE") && xml.contains("http://")) {
                        xxeFound = true;
                    }
                }
                zis.closeEntry();
            }
        }

        assertTrue(entriesFound.contains("[Content_Types].xml"), "Must contain [Content_Types].xml");
        assertTrue(entriesFound.contains("_rels/.rels"), "Must contain _rels/.rels");
        assertTrue(entriesFound.contains("word/document.xml"), "Must contain word/document.xml");
        assertTrue(xxeFound, "word/document.xml must contain collaborator XXE payload");
    }

    @Test
    @DisplayName("UploadPayloadGenerator: All 24 modules generate payloads and support category toggles")
    void testAll24ScanningModulesAndCategoryToggles() {
        UploadScannerConfig config = new UploadScannerConfig();

        // 1. Test category toggle
        config.selectAll(false);
        config.selectCategory("Server RCE", true);
        assertTrue(config.isTestPhp());
        assertTrue(config.isTestJsp());
        assertTrue(config.isTestAsp());
        assertTrue(config.isTestHtaccess());
        assertTrue(config.isTestWebConfig());
        assertTrue(config.isTestCgi());
        assertTrue(config.isTestSsiEsi());
        assertFalse(config.isTestImageTragick());
        assertFalse(config.isTestXssSvg());

        // 2. Enable all 24 modules across 5 categories
        config.selectAll(true);
        String collabSubdomain = "littlespidy-test.burpcollaborator.net";
        List<PayloadDefinition> payloads = UploadPayloadGenerator.generatePayloads(config, "avatar.png", collabSubdomain);

        assertNotNull(payloads);
        assertTrue(payloads.size() >= 35, "All 24 modules should generate >= 35 distinct attack payloads");

        // Verify representative payloads across all 5 categories
        boolean hasPhp = false;
        boolean hasJsp = false;
        boolean hasAspx = false;
        boolean hasHtaccess = false;
        boolean hasWebConfig = false;
        boolean hasCgi = false;
        boolean hasSsi = false;
        boolean hasImageTragick = false;
        boolean hasGhostscript = false;
        boolean hasLibav = false;
        boolean hasDocxXxe = false;
        boolean hasPdf = false;
        boolean hasCsv = false;
        boolean hasHtmlXss = false;
        boolean hasPolyglotJpeg = false;
        boolean hasPolyglotGif = false;
        boolean hasZipSlip = false;
        boolean hasTarSymlink = false;
        boolean hasPixelFlood = false;
        boolean hasXmlBomb = false;
        boolean hasOobPayload = false;

        for (PayloadDefinition p : payloads) {
            String name = p.getName();
            if (name.contains("PHP")) hasPhp = true;
            if (name.contains("JSP")) hasJsp = true;
            if (name.contains("ASP")) hasAspx = true;
            if (name.contains(".htaccess")) hasHtaccess = true;
            if (name.contains("web.config")) hasWebConfig = true;
            if (name.contains("CGI")) hasCgi = true;
            if (name.contains("SSI")) hasSsi = true;
            if (name.contains("ImageTragick")) hasImageTragick = true;
            if (name.contains("Ghostscript")) hasGhostscript = true;
            if (name.contains("LibAVFormat")) hasLibav = true;
            if (name.contains("Word") || name.toLowerCase().contains("docx")) hasDocxXxe = true;
            if (name.contains("PDF")) hasPdf = true;
            if (name.contains("CSV")) hasCsv = true;
            if (name.contains("HTML Stored XSS")) hasHtmlXss = true;
            if (name.contains("JPEG + JavaScript CSP Polyglot")) hasPolyglotJpeg = true;
            if (name.contains("GIF89a + JavaScript CSP Polyglot")) hasPolyglotGif = true;
            if (name.contains("Zip Slip")) hasZipSlip = true;
            if (name.contains("TAR") && name.contains("Symlink")) hasTarSymlink = true;
            if (name.contains("Pixel Flood")) hasPixelFlood = true;
            if (name.contains("Billion Laughs")) hasXmlBomb = true;
            if (p.isOob()) {
                hasOobPayload = true;
                assertEquals(collabSubdomain, p.getCollaboratorSubdomain());
            }
        }

        assertTrue(hasPhp, "PHP payloads present");
        assertTrue(hasJsp, "JSP payloads present");
        assertTrue(hasAspx, "ASPX payloads present");
        assertTrue(hasHtaccess, "htaccess payloads present");
        assertTrue(hasWebConfig, "web.config payloads present");
        assertTrue(hasCgi, "CGI payloads present");
        assertTrue(hasSsi, "SSI payloads present");
        assertTrue(hasImageTragick, "ImageTragick payloads present");
        assertTrue(hasGhostscript, "Ghostscript payloads present");
        assertTrue(hasLibav, "LibAVFormat payloads present");
        assertTrue(hasDocxXxe, "DOCX XXE payloads present");
        assertTrue(hasPdf, "PDF payloads present");
        assertTrue(hasCsv, "CSV payloads present");
        assertTrue(hasHtmlXss, "HTML XSS payloads present");
        assertTrue(hasPolyglotJpeg, "Polyglot JPEG payloads present");
        assertTrue(hasPolyglotGif, "Polyglot GIF payloads present");
        assertTrue(hasZipSlip, "Zip Slip payloads present");
        assertTrue(hasTarSymlink, "TAR symlink payloads present");
        assertTrue(hasPixelFlood, "Pixel Flood payloads present");
        assertTrue(hasXmlBomb, "XML Bomb payloads present");
        assertTrue(hasOobPayload, "OOB Collaborator payloads flagged properly");
    }

    @Test
    @DisplayName("ReDownloaderEngine: Cookie and Auth Header Detection")
    void testCookieAndAuthHeaderDetection() {
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("Cookie"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("cookie"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("Authorization"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("authorization"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("Proxy-Authorization"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("X-Auth-Token"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("X-API-Key"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("ApiKey"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("Session-Id"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("X-Access-Token"));
        assertTrue(ReDownloaderEngine.isCookieOrAuthHeader("Bearer-Token"));

        assertFalse(ReDownloaderEngine.isCookieOrAuthHeader("Host"));
        assertFalse(ReDownloaderEngine.isCookieOrAuthHeader("Content-Type"));
        assertFalse(ReDownloaderEngine.isCookieOrAuthHeader("Content-Length"));
        assertFalse(ReDownloaderEngine.isCookieOrAuthHeader("User-Agent"));
        assertFalse(ReDownloaderEngine.isCookieOrAuthHeader("Accept"));
        assertFalse(ReDownloaderEngine.isCookieOrAuthHeader("Connection"));
        assertFalse(ReDownloaderEngine.isCookieOrAuthHeader(""));
        assertFalse(ReDownloaderEngine.isCookieOrAuthHeader(null));
    }

    @Test
    @DisplayName("Allowed Extensions: Full payload generation across all categories and custom extensions")
    void testAllowedExtensionsPayloadGeneration() {
        UploadScannerConfig config = new UploadScannerConfig();
        config.setCustomExtensions("bak, sql, log");

        List<PayloadDefinition> payloads = UploadPayloadGenerator.generateAllowedExtensionPayloadsOnly(config, "upload.jpg");
        assertNotNull(payloads);
        assertTrue(payloads.size() >= 35, "Expected comprehensive list of allowed extension probes (>= 35), got: " + payloads.size());

        Set<String> filenames = new HashSet<>();
        Set<String> contentTypes = new HashSet<>();
        for (PayloadDefinition p : payloads) {
            assertEquals("Allowed Extensions", p.getCategory());
            filenames.add(p.getFilename());
            contentTypes.add(p.getContentType());
            assertTrue(p.getContent().length > 0, "Payload content must not be empty for " + p.getFilename());
        }

        // Verify Images
        assertTrue(filenames.contains("probe_test.jpg"));
        assertTrue(filenames.contains("probe_test.jpeg"));
        assertTrue(filenames.contains("probe_test.png"));
        assertTrue(filenames.contains("probe_test.gif"));
        assertTrue(filenames.contains("probe_test.webp"));
        assertTrue(filenames.contains("probe_test.bmp"));
        assertTrue(filenames.contains("probe_test.svg"));
        assertTrue(filenames.contains("probe_test.ico"));
        assertTrue(filenames.contains("probe_test.tiff"));
        assertTrue(filenames.contains("probe_test.avif"));

        // Verify Documents
        assertTrue(filenames.contains("probe_test.txt"));
        assertTrue(filenames.contains("probe_test.pdf"));
        assertTrue(filenames.contains("probe_test.doc"));
        assertTrue(filenames.contains("probe_test.docx"));
        assertTrue(filenames.contains("probe_test.xls"));
        assertTrue(filenames.contains("probe_test.xlsx"));
        assertTrue(filenames.contains("probe_test.ppt"));
        assertTrue(filenames.contains("probe_test.pptx"));
        assertTrue(filenames.contains("probe_test.csv"));
        assertTrue(filenames.contains("probe_test.rtf"));
        assertTrue(filenames.contains("probe_test.odt"));

        // Verify Web & Data
        assertTrue(filenames.contains("probe_test.json"));
        assertTrue(filenames.contains("probe_test.xml"));
        assertTrue(filenames.contains("probe_test.html"));
        assertTrue(filenames.contains("probe_test.js"));
        assertTrue(filenames.contains("probe_test.css"));
        assertTrue(filenames.contains("probe_test.yaml"));

        // Verify Archives
        assertTrue(filenames.contains("probe_test.zip"));
        assertTrue(filenames.contains("probe_test.tar"));
        assertTrue(filenames.contains("probe_test.gz"));
        assertTrue(filenames.contains("probe_test.7z"));
        assertTrue(filenames.contains("probe_test.rar"));

        // Verify Media
        assertTrue(filenames.contains("probe_test.mp3"));
        assertTrue(filenames.contains("probe_test.wav"));
        assertTrue(filenames.contains("probe_test.mp4"));
        assertTrue(filenames.contains("probe_test.avi"));
        assertTrue(filenames.contains("probe_test.mov"));
        assertTrue(filenames.contains("probe_test.mkv"));
        assertTrue(filenames.contains("probe_test.ogg"));

        // Verify Custom
        assertTrue(filenames.contains("probe_custom.bak"));
        assertTrue(filenames.contains("probe_custom.sql"));
        assertTrue(filenames.contains("probe_custom.log"));

        // Verify Content-Types
        assertTrue(contentTypes.contains("image/jpeg"));
        assertTrue(contentTypes.contains("image/png"));
        assertTrue(contentTypes.contains("text/plain"));
        assertTrue(contentTypes.contains("application/pdf"));
        assertTrue(contentTypes.contains("application/zip"));
        assertTrue(contentTypes.contains("video/mp4"));
    }

    @Test
    @DisplayName("Allowed Extensions: Valid binary magic bytes and file header signatures")
    void testAllowedExtensionsMagicBytesIntegrity() throws IOException {
        // 1. JPEG
        byte[] jpeg = UploadPayloadGenerator.createMinimalJpeg();
        assertEquals((byte) 0xFF, jpeg[0]);
        assertEquals((byte) 0xD8, jpeg[1]);
        assertEquals((byte) 0xFF, jpeg[jpeg.length - 2]);
        assertEquals((byte) 0xD9, jpeg[jpeg.length - 1]);

        // 2. PNG
        byte[] png = UploadPayloadGenerator.createMinimalPng();
        assertEquals((byte) 0x89, png[0]);
        assertEquals((byte) 0x50, png[1]); // P
        assertEquals((byte) 0x4E, png[2]); // N
        assertEquals((byte) 0x47, png[3]); // G

        // 3. GIF
        byte[] gif = UploadPayloadGenerator.createMinimalGif();
        assertEquals("GIF89a", new String(gif, 0, 6));

        // 4. WebP
        byte[] webp = UploadPayloadGenerator.createMinimalWebp();
        assertEquals("RIFF", new String(webp, 0, 4));
        assertEquals("WEBP", new String(webp, 8, 4));

        // 5. BMP
        byte[] bmp = UploadPayloadGenerator.createMinimalBmp();
        assertEquals("BM", new String(bmp, 0, 2));

        // 6. PDF
        byte[] pdf = UploadPayloadGenerator.createMinimalPdf("token123");
        assertTrue(new String(pdf).startsWith("%PDF-1.4"));
        assertTrue(new String(pdf).contains("%%EOF"));

        // 7. ZIP
        byte[] zip = UploadPayloadGenerator.createMinimalZipArchive("token123");
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry ze = zis.getNextEntry();
            assertNotNull(ze);
            assertEquals("probe.txt", ze.getName());
            String text = new String(zis.readAllBytes());
            assertTrue(text.contains("token123"));
        }

        // 8. 7z
        byte[] sevenZ = UploadPayloadGenerator.createMinimal7zArchive();
        assertEquals((byte) 0x37, sevenZ[0]); // '7'
        assertEquals((byte) 0x7A, sevenZ[1]); // 'z'

        // 9. RAR
        byte[] rar = UploadPayloadGenerator.createMinimalRarArchive();
        assertEquals("Rar!", new String(rar, 0, 4));

        // 10. MP3
        byte[] mp3 = UploadPayloadGenerator.createMinimalMp3();
        assertEquals("ID3", new String(mp3, 0, 3));

        // 11. WAV
        byte[] wav = UploadPayloadGenerator.createMinimalWav();
        assertEquals("RIFF", new String(wav, 0, 4));
        assertEquals("WAVE", new String(wav, 8, 4));

        // 12. MP4
        byte[] mp4 = UploadPayloadGenerator.createMinimalMp4();
        assertEquals("ftyp", new String(mp4, 4, 4));
        assertEquals("isom", new String(mp4, 8, 4));

        // 13. TAR
        byte[] tar = UploadPayloadGenerator.createMinimalTarArchive("token123");
        assertEquals(1024, tar.length);
        assertEquals("ustar", new String(tar, 257, 5));
    }

    @Test
    @DisplayName("Allowed Extensions: Config category toggles and selectCategory integration")
    void testAllowedExtensionsConfigToggles() {
        UploadScannerConfig config = new UploadScannerConfig();

        // Check defaults
        assertTrue(config.isTestAllowedExtensions());
        assertTrue(config.isTestExtImages());
        assertTrue(config.isTestExtDocuments());
        assertTrue(config.isTestExtWebData());
        assertTrue(config.isTestExtArchives());
        assertTrue(config.isTestExtMedia());

        // Toggle category off
        config.selectCategory("Allowed Extensions", false);
        assertFalse(config.isTestAllowedExtensions());
        assertFalse(config.isTestExtImages());
        assertFalse(config.isTestExtDocuments());
        assertFalse(config.isTestExtWebData());
        assertFalse(config.isTestExtArchives());
        assertFalse(config.isTestExtMedia());

        // Enable only Images
        config.setTestAllowedExtensions(true);
        config.setTestExtImages(true);
        List<PayloadDefinition> payloads = UploadPayloadGenerator.generateAllowedExtensionPayloadsOnly(config, "avatar.png");
        assertFalse(payloads.isEmpty());
        for (PayloadDefinition p : payloads) {
            assertTrue(p.getContentType().startsWith("image/"));
        }
    }

    @Test
    @DisplayName("UploadLogTableModel: Filter by Stage 'Probe'")
    void testLogTableModelFilterByProbe() {
        UploadLogTableModel model = new UploadLogTableModel();

        UploadEntry e1 = new UploadEntry(1, StageType.EXTENSION_PROBE, "POST", (short) 200, "Allowed Extension: JPEG (.jpg)",
                1024, "https://example.com/upload", null, "", null, null);
        UploadEntry e2 = new UploadEntry(2, StageType.EXTENSION_PROBE, "POST", (short) 415, "Allowed Extension: Plain Text (.txt)",
                256, "https://example.com/upload", null, "", null, null);
        UploadEntry e3 = new UploadEntry(3, StageType.UPLOAD, "POST", (short) 200, "PHP Web Shell",
                512, "https://example.com/upload", null, "", null, null);

        model.addEntry(e1);
        model.addEntry(e2);
        model.addEntry(e3);

        assertEquals(3, model.getRowCount());

        // Filter for "Probe"
        model.applyFilters(Set.of("Probe"), null, null, "");
        assertEquals(2, model.getRowCount());
        assertEquals("Allowed Extension: JPEG (.jpg)", model.getValueAt(0, 4));
        assertEquals("Allowed Extension: Plain Text (.txt)", model.getValueAt(1, 4));

        // Filter for Status 2xx + Probe
        model.applyFilters(Set.of("Probe"), Set.of("2xx"), null, "");
        assertEquals(1, model.getRowCount());
        assertEquals(200, model.getValueAt(0, 3));
    }

    @Test
    @DisplayName("UploadScanExecutor: Extract filename from §...§ marker in path, body, or fallback")
    void testExtractFilenameMarkers() {
        // 1. Path marker
        HttpRequest pathReq = createMockRequest("/api/upload?file=§avatar_test.png§", Collections.emptyList(), "test body");
        assertEquals("avatar_test.png", UploadScanExecutor.extractFilenameFromRequest(pathReq));

        // 2. Body marker
        HttpRequest bodyReq = createMockRequest("/api/upload", Collections.emptyList(), "{\"filename\":\"§document.pdf§\"}");
        assertEquals("document.pdf", UploadScanExecutor.extractFilenameFromRequest(bodyReq));

        // 3. Fallback to multipart filename="..."
        String multipart = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
                "Content-Disposition: form-data; name=\"file\"; filename=\"my_photo.jpeg\"\r\n" +
                "Content-Type: image/jpeg\r\n\r\n[data]\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--";
        HttpRequest fallbackReq = createMockRequest("/api/upload", Collections.emptyList(), multipart);
        assertEquals("my_photo.jpeg", UploadScanExecutor.extractFilenameFromRequest(fallbackReq));
    }

    @Test
    @DisplayName("UploadScanExecutor: Multi-location marker replacement across path, headers, and body simultaneously")
    void testMultiLocationMarkerReplacement() {
        String path = "/api/storage/§test_orig.png§?download_name=§test_orig.png§";
        List<HttpHeader> headers = List.of(
                createHeader("Host", "example.com"),
                createHeader("X-File-Name", "§test_orig.png§"),
                createHeader("X-Upload-Slug", "upload_${FILENAME}")
        );
        String body = "------WebKitBoundary123\r\n" +
                "Content-Disposition: form-data; name=\"upload\"; filename=\"§test_orig.png§\"\r\n" +
                "Content-Type: image/png\r\n\r\n" +
                "ORIGINAL_FILE_BYTES_HERE\r\n" +
                "------WebKitBoundary123--";

        HttpRequest baseReq = createMockRequest(path, headers, body);
        PayloadDefinition payload = new PayloadDefinition(
                "PHP Webshell",
                "Upload",
                "webshell.php",
                "application/x-php",
                "<?php phpinfo(); ?>".getBytes(),
                "phpinfo"
        );

        HttpRequest modified = UploadScanExecutor.injectPayload(baseReq, payload);
        assertNotNull(modified);

        // Verify Path replaced
        assertEquals("/api/storage/webshell.php?download_name=webshell.php", modified.path());

        // Verify Headers replaced
        Map<String, String> headerMap = new LinkedHashMap<>();
        for (HttpHeader h : modified.headers()) {
            headerMap.put(h.name(), h.value());
        }
        assertEquals("webshell.php", headerMap.get("X-File-Name"));
        assertEquals("upload_webshell.php", headerMap.get("X-Upload-Slug"));

        // Verify Body replaced (filename, Content-Type, and file bytes)
        String modBody = modified.bodyToString();
        assertTrue(modBody.contains("filename=\"webshell.php\""));
        assertTrue(modBody.contains("Content-Type: application/x-php"));
        assertTrue(modBody.contains("<?php phpinfo(); ?>"));
        assertFalse(modBody.contains("ORIGINAL_FILE_BYTES_HERE"));
        assertFalse(modBody.contains("§"));
    }

    @Test
    @DisplayName("UploadPayloadGenerator: Custom allowed extensions parsing and generation")
    void testCustomAllowedExtensions() {
        UploadScannerConfig config = new UploadScannerConfig();
        config.selectCategory("Allowed Extensions", false);
        config.setTestAllowedExtensions(true);
        config.setCustomExtensions("csv, yml, json, .sql");

        List<PayloadDefinition> payloads = UploadPayloadGenerator.generateAllowedExtensionPayloadsOnly(config, "sample.dat");
        assertEquals(4, payloads.size());

        Set<String> filenames = new HashSet<>();
        for (PayloadDefinition p : payloads) {
            filenames.add(p.getFilename());
        }
        assertTrue(filenames.contains("probe_custom.csv"));
        assertTrue(filenames.contains("probe_custom.yml"));
        assertTrue(filenames.contains("probe_custom.json"));
        assertTrue(filenames.contains("probe_custom.sql"));
    }

    // ── Helper methods for mocking Montoya HttpRequest & HttpHeader ──

    private static HttpHeader createHeader(String name, String value) {
        return new HttpHeader() {
            @Override public String name() { return name; }
            @Override public String value() { return value; }
            @Override public String toString() { return name + ": " + value; }
        };
    }

    private static HttpRequest createMockRequest(String path, List<HttpHeader> headers, String body) {
        Map<String, String> headerMap = new LinkedHashMap<>();
        if (headers != null) {
            for (HttpHeader h : headers) {
                headerMap.put(h.name(), h.value());
            }
        }
        return createMockRequestInternal(path, headerMap, body);
    }

    private static HttpRequest createMockRequestInternal(String path, Map<String, String> headers, String body) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> {
                    String mName = method.getName();
                    if ("path".equals(mName)) {
                        return path;
                    }
                    if ("withPath".equals(mName) && args.length == 1) {
                        return createMockRequestInternal((String) args[0], new LinkedHashMap<>(headers), body);
                    }
                    if ("headers".equals(mName)) {
                        List<HttpHeader> list = new ArrayList<>();
                        headers.forEach((k, v) -> list.add(createHeader(k, v)));
                        return list;
                    }
                    if ("withHeader".equals(mName) && args.length == 2 && args[0] instanceof String && args[1] instanceof String) {
                        Map<String, String> nextHeaders = new LinkedHashMap<>(headers);
                        nextHeaders.put((String) args[0], (String) args[1]);
                        return createMockRequestInternal(path, nextHeaders, body);
                    }
                    if ("bodyToString".equals(mName)) {
                        return body;
                    }
                    if ("withBody".equals(mName) && args.length == 1 && args[0] instanceof String) {
                        return createMockRequestInternal(path, new LinkedHashMap<>(headers), (String) args[0]);
                    }
                    if ("method".equals(mName)) {
                        return "POST";
                    }
                    if ("url".equals(mName)) {
                        return "https://example.com" + path;
                    }
                    return null;
                }
        );
    }
}
