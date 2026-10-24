// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import com.littlespidy.quickhelper.model.ExtensionItem_littlespidy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionDownloaderServiceTest_littlespidy {

    private ExtensionDownloaderService_littlespidy service;

    @BeforeEach
    void setUp() {
        service = new ExtensionDownloaderService_littlespidy(null);
    }

    @AfterEach
    void tearDown() {
        if (service != null) {
            service.shutdown();
        }
    }

    @Test
    void testDefaultDownloadDirectory() {
        Path defaultDir = service.getDefaultDownloadDirectory();
        assertNotNull(defaultDir);
        assertTrue(defaultDir.toString().contains("burpsuite-extensions"));
    }

    @Test
    void testEmptyBatchDoesNotRun(@TempDir Path tempDir) {
        service.downloadAllAsync(Collections.emptyList(), tempDir);
        assertFalse(service.isRunning());
    }

    @Test
    void testListenerReceivesBatchEvents(@TempDir Path tempDir) throws Exception {
        ExtensionItem_littlespidy item = new ExtensionItem_littlespidy(
                "test-ext",
                "Test Extension",
                "Testing",
                "test-extension-1.0.0.jar",
                "http://127.0.0.1:1/nonexistent.jar",
                "1.0 MB",
                "Description"
        );

        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean batchCompletedCalled = new AtomicBoolean(false);

        service.addListener(new ExtensionDownloaderService_littlespidy.DownloadListener() {
            @Override
            public void onItemStarted(ExtensionItem_littlespidy item) {}

            @Override
            public void onItemProgress(ExtensionItem_littlespidy item, int percent, long bytesRead, long totalBytes) {}

            @Override
            public void onItemCompleted(ExtensionItem_littlespidy item, Path savedPath) {}

            @Override
            public void onItemFailed(ExtensionItem_littlespidy item, String errorMessage) {}

            @Override
            public void onBatchProgress(int completedCount, int totalCount, ExtensionItem_littlespidy currentItem) {}

            @Override
            public void onBatchCompleted(int successCount, int failedCount, Path destinationDir) {
                batchCompletedCalled.set(true);
                latch.countDown();
            }

            @Override
            public void onLog(String message, boolean isError) {}
        });

        service.downloadSingleAsync(item, tempDir);
        boolean finished = latch.await(10, TimeUnit.SECONDS);

        assertTrue(finished, "Download batch should complete or fail within timeout");
        assertTrue(batchCompletedCalled.get());
        assertEquals(ExtensionItem_littlespidy.Status.FAILED, item.getStatus());
    }
}
