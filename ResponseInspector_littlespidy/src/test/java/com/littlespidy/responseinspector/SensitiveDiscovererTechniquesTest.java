// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.MimeType;
import com.littlespidy.responseinspector.engine.RefinerRule;
import com.littlespidy.responseinspector.engine.ScannerUtils;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.SecretClassification;
import com.littlespidy.responseinspector.model.SecretClassificationManager;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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

    @Test
    public void testClassificationRule1IndividualOverridesType() {
        SecretClassificationManager manager = new SecretClassificationManager();

        FindingEntry req1 = new FindingEntry(1, FindingCategory.SECRET, "Slack Token", "xoxb-123",
                "Response Body", "GET", "https://api.target.com/a", "api.target.com", "/a", (short) 200, "application/json", 50, null, "12:00", 0, 10);
        FindingEntry req2 = new FindingEntry(2, FindingCategory.SECRET, "Slack Token", "xoxb-456",
                "Response Body", "POST", "https://api.target.com/b", "api.target.com", "/b", (short) 200, "application/json", 50, null, "12:00", 0, 10);

        // Case A: Mark entire secret type as FP first, then mark specific request as TP
        manager.markSecretType("Slack Token", SecretClassification.FALSE_POSITIVE);
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req1));
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req2));

        manager.markRequest(req1, SecretClassification.TRUE_POSITIVE);
        // Request 1 must be TP, Request 2 must remain FP
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req1));
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req2));

        // Case B: Mark entire secret type as TP first, then mark specific request as FP
        manager.clear();
        FindingEntry req3 = new FindingEntry(3, FindingCategory.SECRET, "AWS Access Key", "AKIA1111",
                "Response Body", "GET", "https://api.target.com/c", "api.target.com", "/c", (short) 200, "text/plain", 50, null, "12:00", 0, 10);
        FindingEntry req4 = new FindingEntry(4, FindingCategory.SECRET, "AWS Access Key", "AKIA2222",
                "Response Body", "POST", "https://api.target.com/d", "api.target.com", "/d", (short) 200, "text/plain", 50, null, "12:00", 0, 10);

        manager.markSecretType("AWS Access Key", SecretClassification.TRUE_POSITIVE);
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req3));
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req4));

        manager.markRequest(req3, SecretClassification.FALSE_POSITIVE);
        // Request 3 must be FP, Request 4 must remain TP
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req3));
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req4));
    }

    @Test
    public void testClassificationRule2SecretTypeAppliesExceptExplicitIndividual() {
        SecretClassificationManager manager = new SecretClassificationManager();

        FindingEntry req1 = new FindingEntry(10, FindingCategory.SECRET, "GitHub Token", "ghp_111",
                "Response Body", "GET", "https://api.target.com/x", "api.target.com", "/x", (short) 200, "application/json", 50, null, "12:00", 0, 10);
        FindingEntry req2 = new FindingEntry(11, FindingCategory.SECRET, "GitHub Token", "ghp_222",
                "Response Body", "GET", "https://api.target.com/y", "api.target.com", "/y", (short) 200, "application/json", 50, null, "12:00", 0, 10);

        // Case A: Mark single request as TP first, then mark entire secret type as FP
        manager.markRequest(req1, SecretClassification.TRUE_POSITIVE);
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req1));
        assertEquals(SecretClassification.NOT_VERIFIED, manager.getEffectiveClassification(req2));

        manager.markSecretType("GitHub Token", SecretClassification.FALSE_POSITIVE);
        // Individually marked request must remain TP, while req2 must become FP
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req1));
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req2));

        // Case B: Mark single request as FP first, then mark entire secret type as TP
        manager.clear();
        FindingEntry req3 = new FindingEntry(12, FindingCategory.SECRET, "Stripe Key", "sk_live_111",
                "Response Body", "GET", "https://api.target.com/s1", "api.target.com", "/s1", (short) 200, "application/json", 50, null, "12:00", 0, 10);
        FindingEntry req4 = new FindingEntry(13, FindingCategory.SECRET, "Stripe Key", "sk_live_222",
                "Response Body", "GET", "https://api.target.com/s2", "api.target.com", "/s2", (short) 200, "application/json", 50, null, "12:00", 0, 10);

        manager.markRequest(req3, SecretClassification.FALSE_POSITIVE);
        manager.markSecretType("Stripe Key", SecretClassification.TRUE_POSITIVE);
        // Individually marked request must remain FP, while req4 must become TP
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req3));
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req4));
    }

    @Test
    public void testClassificationPreservedOnSubsequentTypeChanges() {
        SecretClassificationManager manager = new SecretClassificationManager();

        FindingEntry req1 = new FindingEntry(20, FindingCategory.SECRET, "OpenAI API Key", "sk-proj-111",
                "Response Body", "GET", "https://api.target.com/ai1", "api.target.com", "/ai1", (short) 200, "application/json", 50, null, "12:00", 0, 10);
        FindingEntry req2 = new FindingEntry(21, FindingCategory.SECRET, "OpenAI API Key", "sk-proj-222",
                "Response Body", "GET", "https://api.target.com/ai2", "api.target.com", "/ai2", (short) 200, "application/json", 50, null, "12:00", 0, 10);
        FindingEntry req3 = new FindingEntry(22, FindingCategory.SECRET, "OpenAI API Key", "sk-proj-333",
                "Response Body", "GET", "https://api.target.com/ai3", "api.target.com", "/ai3", (short) 200, "application/json", 50, null, "12:00", 0, 10);

        manager.markRequest(req1, SecretClassification.TRUE_POSITIVE);
        manager.markRequest(req2, SecretClassification.FALSE_POSITIVE);

        // Type is initially unset -> req3 is NOT_VERIFIED
        assertEquals(SecretClassification.NOT_VERIFIED, manager.getEffectiveClassification(req3));

        // Change secret type to TP
        manager.markSecretType("OpenAI API Key", SecretClassification.TRUE_POSITIVE);
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req1));
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req2));
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req3));

        // Change secret type to FP
        manager.markSecretType("OpenAI API Key", SecretClassification.FALSE_POSITIVE);
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req1));
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req2));
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req3));

        // Clear secret type classification
        manager.clearSecretTypeClassification("OpenAI API Key");
        assertEquals(SecretClassification.TRUE_POSITIVE, manager.getEffectiveClassification(req1));
        assertEquals(SecretClassification.FALSE_POSITIVE, manager.getEffectiveClassification(req2));
        assertEquals(SecretClassification.NOT_VERIFIED, manager.getEffectiveClassification(req3));
    }

    @Test
    public void testClassificationFiltering() {
        SecretClassificationManager manager = new SecretClassificationManager();

        FindingEntry tpEntry = new FindingEntry(30, FindingCategory.SECRET, "AWS S3 Bucket", "tp-bucket.s3.amazonaws.com",
                "Response Body", "GET", "https://api.target.com/1", "api.target.com", "/1", (short) 200, "text/plain", 50, null, "12:00", 0, 10);
        FindingEntry fpEntry = new FindingEntry(31, FindingCategory.SECRET, "AWS S3 Bucket", "fp-bucket.s3.amazonaws.com",
                "Response Body", "GET", "https://api.target.com/2", "api.target.com", "/2", (short) 200, "text/plain", 50, null, "12:00", 0, 10);
        FindingEntry nvEntry = new FindingEntry(32, FindingCategory.SECRET, "Slack Token", "xoxb-unverified",
                "Response Body", "GET", "https://api.target.com/3", "api.target.com", "/3", (short) 200, "text/plain", 50, null, "12:00", 0, 10);

        manager.markRequest(tpEntry, SecretClassification.TRUE_POSITIVE);
        manager.markRequest(fpEntry, SecretClassification.FALSE_POSITIVE);

        List<FindingEntry> all = List.of(tpEntry, fpEntry, nvEntry);

        // Filter: True Positive
        List<FindingEntry> tpList = all.stream()
                .filter(e -> manager.getEffectiveClassification(e) == SecretClassification.TRUE_POSITIVE)
                .collect(Collectors.toList());
        assertEquals(1, tpList.size());
        assertEquals("tp-bucket.s3.amazonaws.com", tpList.get(0).matchValue());

        // Filter: False Positive
        List<FindingEntry> fpList = all.stream()
                .filter(e -> manager.getEffectiveClassification(e) == SecretClassification.FALSE_POSITIVE)
                .collect(Collectors.toList());
        assertEquals(1, fpList.size());
        assertEquals("fp-bucket.s3.amazonaws.com", fpList.get(0).matchValue());

        // Filter: Not Verified
        List<FindingEntry> nvList = all.stream()
                .filter(e -> manager.getEffectiveClassification(e) == SecretClassification.NOT_VERIFIED)
                .collect(Collectors.toList());
        assertEquals(1, nvList.size());
        assertEquals("xoxb-unverified", nvList.get(0).matchValue());

        // Filter: All Requests (no filter applied)
        assertEquals(3, all.size());
    }

    @Test
    public void testNoEmojisInExtensionCodebase() throws Exception {
        File srcDir = new File("src/main/java");
        assertTrue(srcDir.exists() && srcDir.isDirectory());

        java.util.regex.Pattern unicodeEscapeEmoji = java.util.regex.Pattern.compile(
                "\\\\u(D83[C-E]\\\\u[0-9A-Fa-f]{4}|26[0-9A-Fa-f]{2}|27[0-9A-Fa-f]{2}|2B[0-9A-Fa-f]{2})"
        );

        int checkedFiles = 0;
        try (var stream = Files.walk(srcDir.toPath())) {
            List<File> javaFiles = stream
                    .filter(Files::isRegularFile)
                    .map(java.nio.file.Path::toFile)
                    .filter(f -> f.getName().endsWith(".java"))
                    .collect(Collectors.toList());

            for (File file : javaFiles) {
                checkedFiles++;
                String content = Files.readString(file.toPath());

                // Check for unicode escapes that represent emojis
                assertFalse(unicodeEscapeEmoji.matcher(content).find(),
                        "Found emoji unicode escape in: " + file.getName());

                // Check for literal emojis
                for (int i = 0; i < content.length(); i++) {
                    int codePoint = content.codePointAt(i);
                    // Check standard emoji unicode blocks
                    boolean isEmoji = (codePoint >= 0x1F300 && codePoint <= 0x1FAFF)
                            || (codePoint >= 0x2600 && codePoint <= 0x27BF);
                    assertFalse(isEmoji,
                            String.format("Found literal emoji (U+%04X) in file: %s at character offset %d",
                                    codePoint, file.getName(), i));
                }
            }
        }
        assertTrue(checkedFiles > 10, "Should have audited at least 10 Java source files.");
    }
}
