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

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
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
        // MontoyaApi is null in unit tests; fallback behavior applies
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
    public void testSaveAndReloadDataFidelity() throws Exception {
        ResponseScanEngine engine = new ResponseScanEngine();
        InScopeDomainManager domainManager = new InScopeDomainManager();

        // 1. Setup in-scope domains
        domainManager.addDomain("example.com");
        domainManager.addDomain("api.target.com");

        // 2. Setup passwords
        PasswordScanner pwScanner = engine.getPasswordScanner();
        pwScanner.addPassword("SuperSecretP@ss123");
        pwScanner.addPassword("Admin#2026!Key");

        // 3. Setup sample findings with mock/empty HttpRequestResponse
        InspectorDataStore secretStore = engine.getDataStore(FindingCategory.SECRET);
        InspectorDataStore errorStore = engine.getDataStore(FindingCategory.ERROR);

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
                null,
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

        // 5. Save data
        storageManager.bindEngines(engine, domainManager);
        boolean saveOk = storageManager.saveData(engine, domainManager);
        assertTrue(saveOk, "saveData should return true");

        // Verify files exist on disk
        File findingsFile = new File(testStorageDir, "findings.dat");
        File configFile = new File(testStorageDir, "config.properties");
        assertTrue(findingsFile.exists(), "findings.dat must exist on disk");
        assertTrue(configFile.exists(), "config.properties must exist on disk");
        assertTrue(findingsFile.length() > 0, "findings.dat must not be empty");

        // Verify magic header and format version in binary file
        try (DataInputStream dis = new DataInputStream(new FileInputStream(findingsFile))) {
            int magic = dis.readInt();
            assertEquals(0x52494644, magic, "Magic header must be 'RIFD' (0x52494644)");
            int version = dis.readInt();
            assertEquals(1, version, "Format version must be 1");
            int count = dis.readInt();
            assertEquals(3, count, "Should have stored 3 findings");
        }

        // 6. Reload data into a fresh engine and domain manager
        ResponseScanEngine freshEngine = new ResponseScanEngine();
        InScopeDomainManager freshDomainManager = new InScopeDomainManager();

        PersistentStorageManager loader = new PersistentStorageManager(null);
        loader.setStorageDirectory(testStorageDir);
        loader.bindEngines(freshEngine, freshDomainManager);

        int loadedCount = loader.loadData(freshEngine, freshDomainManager);
        assertEquals(3, loadedCount, "Should load 3 findings");

        // Verify findings in stores
        assertEquals(2, freshEngine.getDataStore(FindingCategory.SECRET).size());
        assertEquals(1, freshEngine.getDataStore(FindingCategory.ERROR).size());

        // Verify in-scope domains restoration
        Set<String> domains = freshDomainManager.getAllDomains();
        assertTrue(domains.contains("example.com"));
        assertTrue(domains.contains("api.target.com"));

        // Verify passwords restoration
        List<String> passwords = freshEngine.getPasswordScanner().getPasswords();
        assertTrue(passwords.contains("SuperSecretP@ss123"));
        assertTrue(passwords.contains("Admin#2026!Key"));

        // Verify classification restoration & precedence rules
        SecretClassificationManager freshScm = freshEngine.getSecretClassificationManager();
        assertEquals(SecretClassification.FALSE_POSITIVE, freshScm.getTypeClassification("AWS S3 Bucket"));

        FindingEntry loadedSecret1 = freshEngine.getDataStore(FindingCategory.SECRET).getAllEntries().stream()
                .filter(f -> f.matchValue().equals("corp-backup-2026.s3.amazonaws.com"))
                .findFirst()
                .orElse(null);
        assertNotNull(loadedSecret1);
        assertEquals(SecretClassification.TRUE_POSITIVE, freshScm.getEffectiveClassification(loadedSecret1),
                "Individual classification TP must be preserved over secret type FP");

        loader.shutdown();
    }

    @Test
    public void testDeleteStoredData() {
        ResponseScanEngine engine = new ResponseScanEngine();
        InScopeDomainManager domainManager = new InScopeDomainManager();

        domainManager.addDomain("persisted-domain.test");
        engine.getDataStore(FindingCategory.COMMENT).addEntry(new FindingEntry(
                1,
                FindingCategory.COMMENT,
                "TODO Developer Comment",
                "TODO: remove dev key",
                "Response Body",
                "GET",
                "https://persisted-domain.test",
                "persisted-domain.test",
                "/",
                (short) 200,
                "text/html",
                256,
                null,
                "12:00:00",
                0,
                21
        ));

        storageManager.bindEngines(engine, domainManager);
        storageManager.saveData(engine, domainManager);

        File findingsFile = new File(testStorageDir, "findings.dat");
        File configFile = new File(testStorageDir, "config.properties");
        assertTrue(findingsFile.exists());
        assertTrue(configFile.exists());
        assertTrue(storageManager.getStorageSizeBytes() > 0);

        // Explicitly delete stored data
        boolean deleted = storageManager.deleteStoredData();
        assertTrue(deleted);

        assertFalse(findingsFile.exists(), "findings.dat must be deleted");
        assertFalse(configFile.exists(), "config.properties must be deleted");
        assertTrue(testStorageDir.exists(), "Storage directory itself should remain intact");
        assertEquals(0, storageManager.getStorageSizeBytes());
    }

    @Test
    public void testIsTemporaryProjectFallback() {
        // When api is null, isTemporaryProject must safely return true without exception
        assertTrue(storageManager.isTemporaryProject());
    }
}
