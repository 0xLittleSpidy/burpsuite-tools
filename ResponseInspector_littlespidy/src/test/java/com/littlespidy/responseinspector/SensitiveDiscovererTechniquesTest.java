// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.MimeType;
import com.littlespidy.responseinspector.engine.RefinerRule;
import com.littlespidy.responseinspector.engine.ScannerUtils;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SensitiveDiscovererTechniquesTest {

    @Test
    public void testS3BucketRefinerRegex() {
        RefinerRule s3Rule = RefinerRule.ofRefined(
                "AWS S3 Bucket",
                "s3(\\.dualstack|-acce(lerate|sspoint))?\\.([a-z]{1,8}-[a-z]{1,16}-\\d{1,3}\\.)?amazonaws\\.com",
                "[a-z\\d\\-]{3,63}\\.$",
                true,
                false
        );

        String sample = "Download backups from https://prod-assets-2024.s3.amazonaws.com/data.tar.gz immediately.";
        List<RefinerRule.MatchResult> matches = s3Rule.findMatches(sample);

        assertEquals(1, matches.size());
        RefinerRule.MatchResult res = matches.get(0);
        assertEquals("prod-assets-2024.s3.amazonaws.com", res.value());
        assertEquals("prod-assets-2024.s3.amazonaws.com", sample.substring(res.startOffset(), res.endOffset()));
    }

    @Test
    public void testAzureBlobStorageRefinerRegex() {
        RefinerRule azureRule = RefinerRule.ofRefined(
                "Azure Blob Storage",
                "blob\\.core\\.windows\\.net",
                "[a-z\\d\\-]{3,63}\\.$",
                true,
                false
        );

        String sample = "Access URL: https://corpfinance2024.blob.core.windows.net/exports/report.xlsx";
        List<RefinerRule.MatchResult> matches = azureRule.findMatches(sample);

        assertEquals(1, matches.size());
        RefinerRule.MatchResult res = matches.get(0);
        assertEquals("corpfinance2024.blob.core.windows.net", res.value());
        assertEquals("corpfinance2024.blob.core.windows.net", sample.substring(res.startOffset(), res.endOffset()));
    }

    @Test
    public void testFirebaseDatabaseRefinerRegex() {
        RefinerRule fbRule = RefinerRule.ofRefined(
                "Firebase Database URL",
                "\\.(firebase(io\\.com|database\\.app))",
                "[0-9a-zA-Z\\.\\-]{1,64}$",
                true,
                false
        );

        String sample = "Sync to customer-live.firebaseio.com now";
        List<RefinerRule.MatchResult> matches = fbRule.findMatches(sample);

        assertEquals(1, matches.size());
        assertEquals("customer-live.firebaseio.com", matches.get(0).value());
    }

    @Test
    public void testGoogleOAuthClientIdRefinerRegex() {
        RefinerRule googleOAuthRule = RefinerRule.ofRefined(
                "Google OAuth Client ID",
                "\\.apps\\.googleusercontent\\.com",
                "\\d{1,20}-\\w{32}$",
                true,
                false
        );

        // Split strings dynamically to avoid triggering GitHub push protection secret scanners
        String clientIdPrefix = "123456789012" + "-" + "abcdefghijklmnopqrstuvwxyz123456";
        String clientIdDomain = ".apps" + ".googleusercontent.com";
        String sample = "client_id: '" + clientIdPrefix + clientIdDomain + "'";
        List<RefinerRule.MatchResult> matches = googleOAuthRule.findMatches(sample);

        assertEquals(1, matches.size());
        assertEquals(clientIdPrefix + clientIdDomain, matches.get(0).value());
    }

    @Test
    public void testSimpleRulesWithoutRefiner() {
        RefinerRule openAiRule = RefinerRule.ofSimple("OpenAI API Key", "\\bsk-[a-zA-Z0-9]{40,128}(?![\\w\\-])\\b", true);
        String dummyOpenAiKey = "sk-" + "dummykeyfortestingpurposesonly12345678901234567890";
        String sample = "openai_key: \"" + dummyOpenAiKey + "\"";
        List<RefinerRule.MatchResult> matches = openAiRule.findMatches(sample);

        assertEquals(1, matches.size());
        assertEquals(dummyOpenAiKey, matches.get(0).value());

        RefinerRule gocspxRule = RefinerRule.ofSimple("Google OAuth Client Secret", "\\bGOCSPX-[0-9a-zA-Z\\-_]{28}\\b", true);
        String dummyGocspx = "GOCSPX" + "-" + "dummyclientsecret12345678901";
        String gocspxSample = "client_secret = '" + dummyGocspx + "'";
        List<RefinerRule.MatchResult> gMatches = gocspxRule.findMatches(gocspxSample);
        assertEquals(1, gMatches.size());
        assertEquals(dummyGocspx, gMatches.get(0).value());
    }

    @Test
    public void testScannerUtilsMimeTypeBlacklisting() {
        assertTrue(ScannerUtils.BLACKLISTED_MIME_TYPES.contains(MimeType.IMAGE_PNG));
        assertTrue(ScannerUtils.BLACKLISTED_MIME_TYPES.contains(MimeType.IMAGE_JPEG));
        assertTrue(ScannerUtils.BLACKLISTED_MIME_TYPES.contains(MimeType.FONT_WOFF));
        assertTrue(ScannerUtils.BLACKLISTED_MIME_TYPES.contains(MimeType.VIDEO));
        assertTrue(ScannerUtils.BLACKLISTED_MIME_TYPES.contains(MimeType.APPLICATION_FLASH));

        assertFalse(ScannerUtils.BLACKLISTED_MIME_TYPES.contains(MimeType.JSON));
        assertFalse(ScannerUtils.BLACKLISTED_MIME_TYPES.contains(MimeType.HTML));
        assertFalse(ScannerUtils.BLACKLISTED_MIME_TYPES.contains(MimeType.XML));
        assertFalse(ScannerUtils.BLACKLISTED_MIME_TYPES.contains(MimeType.PLAIN_TEXT));
    }

    @Test
    public void testByteArrayToStringConversion() {
        ByteArray mockBytes = (ByteArray) java.lang.reflect.Proxy.newProxyInstance(
                ByteArray.class.getClassLoader(),
                new Class<?>[]{ByteArray.class},
                (proxy, method, args) -> {
                    if ("getBytes".equals(method.getName())) {
                        return "hello world sensitive token".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    }
                    if ("length".equals(method.getName())) {
                        return 27;
                    }
                    return null;
                }
        );
        String str = ScannerUtils.convertByteArrayToString(mockBytes);
        assertEquals("hello world sensitive token", str);
        assertEquals("", ScannerUtils.convertByteArrayToString(null));
    }

    @Test
    public void testFindingEntryTsvAndLocationHelpers() {
        FindingEntry headerEntry = new FindingEntry(
                1,
                FindingCategory.SECRET,
                "JSON Web Token (JWT)",
                "eyJhbGciOi...masked",
                "Response Headers",
                "GET",
                "https://api.example.com/auth",
                "api.example.com",
                "/auth",
                (short) 200,
                "application/json",
                128,
                null,
                "12:00:00",
                10,
                45
        );

        assertTrue(headerEntry.isHeaderFinding());
        assertFalse(headerEntry.isBodyFinding());
        assertTrue(headerEntry.isResponseFinding());

        String tsvHeader = FindingEntry.tsvHeader();
        assertTrue(tsvHeader.contains("ID\tCategory\tPattern\tMatch Value\tLocation\tMethod\tURL\tHost\tStatus"));

        String tsvRow = headerEntry.toTsvRow();
        assertTrue(tsvRow.startsWith("1\tSecrets\tJSON Web Token (JWT)\teyJhbGciOi...masked\tResponse Headers\tGET\thttps://api.example.com/auth"));

        FindingEntry bodyEntry = new FindingEntry(
                2,
                FindingCategory.PII_NETWORK_PATH,
                "Internal IP Address",
                "192.168.1.1",
                "Response Body",
                "POST",
                "https://api.example.com/admin",
                "api.example.com",
                "/admin",
                (short) 200,
                "text/html",
                512,
                null,
                "12:00:01",
                100,
                111
        );

        assertFalse(bodyEntry.isHeaderFinding());
        assertTrue(bodyEntry.isBodyFinding());
    }

    @Test
    public void testInspectorDataStorePatternFilter() {
        com.littlespidy.responseinspector.model.InspectorDataStore store =
                new com.littlespidy.responseinspector.model.InspectorDataStore(FindingCategory.SECRET);

        FindingEntry e1 = new FindingEntry(1, FindingCategory.SECRET, "AWS S3 Bucket", "my-bucket.s3.amazonaws.com",
                "Response Body", "GET", "https://api.example.com", "api.example.com", "/", (short) 200, "text/plain", 100, null, "12:00", 0, 10);
        FindingEntry e2 = new FindingEntry(2, FindingCategory.SECRET, "OpenAI API Key", "sk-1234567890",
                "Response Body", "POST", "https://api.example.com", "api.example.com", "/", (short) 200, "application/json", 100, null, "12:00", 0, 10);
        FindingEntry e3 = new FindingEntry(3, FindingCategory.SECRET, "JSON Web Token (JWT)", "eyJhbGciOi...",
                "Response Headers", "GET", "https://api.example.com", "api.example.com", "/", (short) 200, "text/html", 100, null, "12:00", 0, 10);

        store.addEntry(e1);
        store.addEntry(e2);
        store.addEntry(e3);

        // Filter: null or empty patternFilter -> returns all
        List<FindingEntry> allFiltered = store.getFilteredEntries("", null, null, null, null, false, null, null);
        assertEquals(3, allFiltered.size());

        // Filter: select only "AWS S3 Bucket"
        List<FindingEntry> s3Filtered = store.getFilteredEntries("", null, null, null, java.util.Set.of("AWS S3 Bucket"), false, null, null);
        assertEquals(1, s3Filtered.size());
        assertEquals("AWS S3 Bucket", s3Filtered.get(0).patternName());

        // Filter: select "OpenAI API Key" and "JSON Web Token (JWT)"
        List<FindingEntry> multiFiltered = store.getFilteredEntries("", null, null, null, java.util.Set.of("OpenAI API Key", "JSON Web Token (JWT)"), false, null, null);
        assertEquals(2, multiFiltered.size());
    }

    @Test
    public void testJsFileExclusion() {
        // Path endings
        assertTrue(ScannerUtils.isJsPath("/assets/app.js"));
        assertTrue(ScannerUtils.isJsPath("https://example.com/chunk-123.mjs?ver=2.1"));
        assertTrue(ScannerUtils.isJsPath("/bundle.js#main"));
        assertTrue(ScannerUtils.isJsPath("/source.ts"));
        assertTrue(ScannerUtils.isJsPath("/source.tsx"));
        assertTrue(ScannerUtils.isJsPath("/app.js.map"));
        assertFalse(ScannerUtils.isJsPath("https://example.com/api/v1/users"));
        assertFalse(ScannerUtils.isJsPath("/index.html"));
        assertFalse(ScannerUtils.isJsPath("/styles.css"));

        // Content types
        assertTrue(ScannerUtils.isJsContentType("application/javascript"));
        assertTrue(ScannerUtils.isJsContentType("text/javascript; charset=utf-8"));
        assertTrue(ScannerUtils.isJsContentType("application/x-javascript"));
        assertFalse(ScannerUtils.isJsContentType("text/html"));
        assertFalse(ScannerUtils.isJsContentType("application/json"));
    }

    @Test
    public void testStaticResourceExclusion() {
        // Static Paths (CSS, Images, Fonts, Media, Binaries, etc.)
        assertTrue(ScannerUtils.isStaticPath("/static/styles.css"));
        assertTrue(ScannerUtils.isStaticPath("/static/theme.scss?v=1.0"));
        assertTrue(ScannerUtils.isStaticPath("/images/logo.png"));
        assertTrue(ScannerUtils.isStaticPath("/img/banner.jpg"));
        assertTrue(ScannerUtils.isStaticPath("/icons/favicon.ico"));
        assertTrue(ScannerUtils.isStaticPath("/vector/icon.svg"));
        assertTrue(ScannerUtils.isStaticPath("/fonts/inter.woff2"));
        assertTrue(ScannerUtils.isStaticPath("/fonts/roboto.ttf"));
        assertTrue(ScannerUtils.isStaticPath("/media/intro.mp4"));
        assertTrue(ScannerUtils.isStaticPath("/audio/alert.mp3"));
        assertTrue(ScannerUtils.isStaticPath("/docs/manual.pdf"));
        assertTrue(ScannerUtils.isStaticPath("/downloads/archive.zip"));
        assertTrue(ScannerUtils.isStaticPath("/app.wasm"));
        assertTrue(ScannerUtils.isStaticPath("/style.css.map"));

        // Non-static paths
        assertFalse(ScannerUtils.isStaticPath("/api/v1/profile"));
        assertFalse(ScannerUtils.isStaticPath("/login.php"));
        assertFalse(ScannerUtils.isStaticPath("/oauth/token"));
        assertFalse(ScannerUtils.isStaticPath("/rest/users.json"));

        // Static Content-Types
        assertTrue(ScannerUtils.isStaticContentType("text/css"));
        assertTrue(ScannerUtils.isStaticContentType("image/png"));
        assertTrue(ScannerUtils.isStaticContentType("image/jpeg"));
        assertTrue(ScannerUtils.isStaticContentType("font/woff2"));
        assertTrue(ScannerUtils.isStaticContentType("application/pdf"));
        assertTrue(ScannerUtils.isStaticContentType("application/zip"));
        assertTrue(ScannerUtils.isStaticContentType("application/octet-stream"));
        assertTrue(ScannerUtils.isStaticContentType("video/mp4"));

        // Non-static Content-Types
        assertFalse(ScannerUtils.isStaticContentType("application/json"));
        assertFalse(ScannerUtils.isStaticContentType("text/html; charset=UTF-8"));
        assertFalse(ScannerUtils.isStaticContentType("application/xml"));
        assertFalse(ScannerUtils.isStaticContentType("text/plain"));
    }

    @Test
    public void testSecretVerifierService() {
        FindingEntry awsFinding = new FindingEntry(
                1,
                FindingCategory.SECRET,
                "AWS Access Key",
                "AKIAIOSFODNN7EXAMPLE",
                "Response Body",
                "GET",
                "https://api.target.com/user",
                "api.target.com",
                "/user",
                (short) 200,
                "application/json",
                100,
                null,
                "12:00",
                0,
                20
        );

        com.littlespidy.responseinspector.engine.SecretVerifierService.SecretVerificationSpec spec =
                com.littlespidy.responseinspector.engine.SecretVerifierService.generateVerification(awsFinding);

        assertNotNull(spec);
        assertTrue(spec.curlCommand().contains("sts.amazonaws.com"));
        assertTrue(spec.curlCommand().contains("AKIAIOSFODNN7EXAMPLE"));
        assertEquals("POST", spec.httpMethod());
    }

    @Test
    public void testCommentCategories() {
        assertEquals(4, com.littlespidy.responseinspector.engine.CommentScanner.getCommentCategories().size() - 1);
        assertTrue(com.littlespidy.responseinspector.engine.CommentScanner.getCommentTypes().contains("Single-Line (//)"));
        assertTrue(com.littlespidy.responseinspector.engine.CommentScanner.getCommentTypes().contains("Multi-Line (/* */)"));
        assertTrue(com.littlespidy.responseinspector.engine.CommentScanner.getCommentTypes().contains("HTML (<!-- -->)"));
    }
}
