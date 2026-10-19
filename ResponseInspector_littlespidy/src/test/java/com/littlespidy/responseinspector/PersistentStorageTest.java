// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.engine.PasswordScanner;
import com.littlespidy.responseinspector.engine.ResponseScanEngine;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InScopeDomainManager;
import com.littlespidy.responseinspector.model.InspectorDataStore;
import com.littlespidy.responseinspector.model.SecretClassification;
import com.littlespidy.responseinspector.model.SecretClassificationManager;
import com.littlespidy.responseinspector.storage.PersistentStorageManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class PersistentStorageTest {

    @TempDir
    Path tempFolder;

    private PersistentStorageManager storageManager;
    private File testStorageDir;

    @BeforeEach
    public void setUp() {
        testStorageDir = tempFolder.resolve("test-storage").toFile();
        testStorageDir.mkdirs();
        storageManager = new PersistentStorageManager(null);
        storageManager.setStorageDirectory(testStorageDir);
    }

    @AfterEach
    public void tearDown() {
        if (storageManager != null) {
            storageManager.shutdown();
        }
    }

    @Test
    public void testDefaultStorageDirectory() {
        File defaultDir = PersistentStorageManager.getDefaultStorageDirectory();
        assertNotNull(defaultDir);
        assertTrue(defaultDir.getAbsolutePath().contains(".BurpSuite"));
        assertTrue(defaultDir.getAbsolutePath().endsWith("response-inspector"));
    }

    @Test
    public void testStorageDirectoryConfiguration() {
        assertEquals(testStorageDir.getAbsolutePath(), storageManager.getStorageDirectory().getAbsolutePath());
        assertTrue(testStorageDir.exists(), "Storage directory should be created");
    }

    @Test
    public void testSaveAndReloadJsonSessionFidelity() throws Exception {
        ResponseScanEngine engine = new ResponseScanEngine();
        InScopeDomainManager domainManager = new InScopeDomainManager();

        // 1. Setup in-scope domains
        domainManager.addDomain("example.com");
        domainManager.addDomain("api.target.com");

        // 2. Setup passwords
        PasswordScanner pwScanner = engine.getPasswordScanner();
        pwScanner.addPassword("SuperSecretP@ss123");
        pwScanner.addPassword("Admin#2026!Key");

        // 3. Setup sample findings with mock HttpRequestResponse
        InspectorDataStore secretStore = engine.getDataStore(FindingCategory.SECRET);
        InspectorDataStore errorStore = engine.getDataStore(FindingCategory.ERROR);

        HttpRequestResponse reqResp = null;

        FindingEntry secretEntry1 = new FindingEntry(
                1,
                FindingCategory.SECRET,
                "AWS S3 Bucket",
                "corp-backup-2026.s3.amazonaws.com",
                "Response Body",
                "GET",
                "https://api.target.com/config/storage",
                "api.target.com",
                "/config/storage",
                (short) 200,
                "application/json",
                128,
                reqResp,
                "12:00:00",
                10,
                42
        );

        FindingEntry secretEntry2 = new FindingEntry(
                2,
                FindingCategory.SECRET,
                "Slack Bot Token",
                "xoxb-999999999-888888888-abcdef123456",
                "Response Body",
                "POST",
                "https://api.target.com/integrations/slack",
                "api.target.com",
                "/integrations/slack",
                (short) 201,
                "application/json",
                256,
                null,
                "12:01:00",
                50,
                88
        );

        FindingEntry errorEntry = new FindingEntry(
                3,
                FindingCategory.ERROR,
                "SQL Syntax Error",
                "You have an error in your SQL syntax",
                "Response Body",
                "GET",
                "https://api.target.com/search?q='",
                "api.target.com",
                "/search",
                (short) 500,
                "text/html",
                512,
                null,
                "12:02:00",
                100,
                138
        );

        secretStore.addEntry(secretEntry1);
        secretStore.addEntry(secretEntry2);
        errorStore.addEntry(errorEntry);

        // 4. Setup classifications
        SecretClassificationManager scm = engine.getSecretClassificationManager();
        scm.markSecretType("AWS S3 Bucket", SecretClassification.FALSE_POSITIVE);
        // Individual classification overrides type classification
        scm.markRequest(secretEntry1, SecretClassification.TRUE_POSITIVE);

        // 5. Save data to JSON session file
        File sessionFile = new File(testStorageDir, "my_session.json");
        storageManager.bindEngines(engine, domainManager);
        storageManager.saveAs(sessionFile);

        // Verify JSON session file exists and is populated
        assertTrue(sessionFile.exists(), "my_session.json must exist on disk");
        assertTrue(sessionFile.length() > 0, "session file must not be empty");

        String jsonContent = Files.readString(sessionFile.toPath());
        assertTrue(jsonContent.contains("corp-backup-2026.s3.amazonaws.com"));
        assertTrue(jsonContent.contains("SuperSecretP@ss123"));
        assertTrue(jsonContent.contains("example.com"));

        // 6. Reload into fresh engine and verify state recovery
        ResponseScanEngine freshEngine = new ResponseScanEngine();
        InScopeDomainManager freshDomainManager = new InScopeDomainManager();

        PersistentStorageManager loader = new PersistentStorageManager(null);
        loader.bindEngines(freshEngine, freshDomainManager);
        loader.openSessionFile(sessionFile);

        assertEquals(2, freshEngine.getDataStore(FindingCategory.SECRET).size());
        assertEquals(1, freshEngine.getDataStore(FindingCategory.ERROR).size());

        Set<String> domains = freshDomainManager.getAllDomains();
        assertTrue(domains.contains("example.com"));
        assertTrue(domains.contains("api.target.com"));

        List<String> passwords = freshEngine.getPasswordScanner().getPasswords();
        assertTrue(passwords.contains("SuperSecretP@ss123"));
        assertTrue(passwords.contains("Admin#2026!Key"));

        SecretClassificationManager freshScm = freshEngine.getSecretClassificationManager();
        assertEquals(SecretClassification.FALSE_POSITIVE, freshScm.getTypeClassification("AWS S3 Bucket"));

        FindingEntry loadedSecret1 = freshEngine.getDataStore(FindingCategory.SECRET).getAllEntries().stream()
                .filter(f -> f.matchValue().equals("corp-backup-2026.s3.amazonaws.com"))
                .findFirst()
                .orElse(null);
        assertNotNull(loadedSecret1);
        assertEquals(SecretClassification.TRUE_POSITIVE, freshScm.getEffectiveClassification(loadedSecret1));

        loader.shutdown();
    }

    @Test
    public void testSessionOffboardRestoresFreshExtensionState() {
        ResponseScanEngine engine = new ResponseScanEngine();
        InScopeDomainManager domainManager = new InScopeDomainManager();

        domainManager.addDomain("offboard-test.com");
        engine.getDataStore(FindingCategory.COMMENT).addEntry(new FindingEntry(
                1,
                FindingCategory.COMMENT,
                "TODO Comment",
                "TODO: check auth",
                "Response Body",
                "GET",
                "https://offboard-test.com",
                "offboard-test.com",
                "/",
                (short) 200,
                "text/html",
                128,
                null,
                "12:00:00",
                0,
                16
        ));

        File sessionFile = new File(testStorageDir, "offboard_test.json");
        storageManager.bindEngines(engine, domainManager);
        storageManager.saveAs(sessionFile);

        assertEquals(1, engine.getDataStore(FindingCategory.COMMENT).size());
        assertNotNull(storageManager.getActiveSessionFile());

        // Perform offboard
        storageManager.offboardSession(null, null);

        // Verify fresh state
        assertNull(storageManager.getActiveSessionFile(), "Active session file must be null after offboarding");
        assertEquals(0, engine.getDataStore(FindingCategory.COMMENT).size(), "Data stores must be cleared after offboarding");
        assertEquals(0, domainManager.getSelectedDomains().size(), "Domains must be deselected");
    }

    @Test
    public void testTemporarySessionRemainsInMemory() {
        storageManager.startTemporarySession();
        assertNull(storageManager.getActiveSessionFile());
        assertTrue(storageManager.isTemporaryProject());
    }

    @Test
    public void testDeleteStoredData() {
        File sessionFile = new File(testStorageDir, "delete_test.json");
        storageManager.saveAs(sessionFile);
        assertTrue(sessionFile.exists());

        boolean deleted = storageManager.deleteStoredData();
        assertTrue(deleted);
        assertFalse(sessionFile.exists());
        assertNull(storageManager.getActiveSessionFile());
    }
}
