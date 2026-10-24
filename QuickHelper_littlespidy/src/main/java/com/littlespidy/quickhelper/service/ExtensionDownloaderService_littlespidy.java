// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.quickhelper.model.ExtensionItem_littlespidy;

import java.awt.Desktop;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service responsible for asynchronous downloading of Burp Suite extension JARs.
 */
public class ExtensionDownloaderService_littlespidy {

    public interface DownloadListener {
        void onItemStarted(ExtensionItem_littlespidy item);
        void onItemProgress(ExtensionItem_littlespidy item, int percent, long bytesRead, long totalBytes);
        void onItemCompleted(ExtensionItem_littlespidy item, Path savedPath);
        void onItemFailed(ExtensionItem_littlespidy item, String errorMessage);
        void onBatchProgress(int completedCount, int totalCount, ExtensionItem_littlespidy currentItem);
        void onBatchCompleted(int successCount, int failedCount, Path destinationDir);
        void onLog(String message, boolean isError);
    }

    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int READ_TIMEOUT_MS = 30000;
    private static final int MAX_REDIRECTS = 6;
    private static final int BUFFER_SIZE = 8192;

    private final MontoyaApi api;
    private final ExecutorService executor;
    private final List<DownloadListener> listeners;
    private final AtomicBoolean isCancelled;
    private final AtomicBoolean isRunning;
    private Future<?> activeBatchFuture;

    public ExtensionDownloaderService_littlespidy(MontoyaApi api) {
        this.api = api;
        this.executor = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "QuickHelper-Downloader-Worker");
            t.setDaemon(true);
            return t;
        });
        this.listeners = new CopyOnWriteArrayList<>();
        this.isCancelled = new AtomicBoolean(false);
        this.isRunning = new AtomicBoolean(false);
    }

    public void addListener(DownloadListener listener) {
        listeners.add(listener);
    }

    public void removeListener(DownloadListener listener) {
        listeners.remove(listener);
    }

    public boolean isRunning() {
        return isRunning.get();
    }

    public Path getDefaultDownloadDirectory() {
        String userHome = System.getProperty("user.home", ".");
        return Paths.get(userHome, "Downloads", "burpsuite-extensions");
    }

    public void cancelDownloads() {
        if (isRunning.get()) {
            isCancelled.set(true);
            if (activeBatchFuture != null) {
                activeBatchFuture.cancel(true);
            }
            log("Download cancellation requested by user.", true);
        }
    }

    public void downloadAllAsync(List<ExtensionItem_littlespidy> items, Path destinationDir) {
        List<ExtensionItem_littlespidy> targets = new ArrayList<>(items);
        startBatch(targets, destinationDir);
    }

    public void downloadSelectedAsync(List<ExtensionItem_littlespidy> items, Path destinationDir) {
        List<ExtensionItem_littlespidy> targets = new ArrayList<>();
        for (ExtensionItem_littlespidy item : items) {
            if (item.isSelected()) {
                targets.add(item);
            }
        }
        startBatch(targets, destinationDir);
    }

    public void downloadSingleAsync(ExtensionItem_littlespidy item, Path destinationDir) {
        List<ExtensionItem_littlespidy> singleList = new ArrayList<>();
        singleList.add(item);
        startBatch(singleList, destinationDir);
    }

    private void startBatch(List<ExtensionItem_littlespidy> targets, Path destinationDir) {
        if (isRunning.get()) {
            log("A download batch is already active. Please wait or cancel it first.", true);
            return;
        }

        if (targets.isEmpty()) {
            log("No extensions selected for download.", true);
            return;
        }

        isCancelled.set(false);
        isRunning.set(true);

        activeBatchFuture = executor.submit(() -> {
            int successCount = 0;
            int failedCount = 0;

            try {
                if (!Files.exists(destinationDir)) {
                    Files.createDirectories(destinationDir);
                    log("Created download destination folder: " + destinationDir, false);
                }

                log("Starting batch download of " + targets.size() + " extension(s) to " + destinationDir, false);

                for (int i = 0; i < targets.size(); i++) {
                    if (isCancelled.get() || Thread.currentThread().isInterrupted()) {
                        log("Batch download was cancelled.", true);
                        break;
                    }

                    ExtensionItem_littlespidy item = targets.get(i);
                    notifyBatchProgress(i, targets.size(), item);

                    boolean success = downloadFile(item, destinationDir);
                    if (success) {
                        successCount++;
                    } else {
                        failedCount++;
                    }
                }
            } catch (Exception e) {
                log("Error during batch download: " + e.getMessage(), true);
            } finally {
                isRunning.set(false);
                notifyBatchCompleted(successCount, failedCount, destinationDir);
                if (api != null) {
                    api.logging().raiseInfoEvent("Quick Helper: Download batch finished. Successfully downloaded "
                            + successCount + " extension(s) to " + destinationDir);
                }
            }
        });
    }

    private boolean downloadFile(ExtensionItem_littlespidy item, Path destinationDir) {
        item.setStatus(ExtensionItem_littlespidy.Status.CONNECTING);
        notifyItemStarted(item);
        log("Downloading " + item.getName() + " (" + item.getJarFileName() + ")...", false);

        Path targetFile = destinationDir.resolve(item.getJarFileName());
        Path tempFile = destinationDir.resolve(item.getJarFileName() + ".tmp");

        HttpURLConnection connection = null;
        InputStream inputStream = null;
        OutputStream outputStream = null;

        try {
            String currentUrl = item.getDownloadUrl();
            int redirectCount = 0;

            while (redirectCount < MAX_REDIRECTS) {
                URI uri = URI.create(currentUrl);
                URL url = uri.toURL();
                connection = (HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
                connection.setReadTimeout(READ_TIMEOUT_MS);
                connection.setInstanceFollowRedirects(false);
                connection.setRequestProperty("User-Agent", "QuickHelper-BurpExtension-littlespidy/1.0");

                int responseCode = connection.getResponseCode();
                if (responseCode == HttpURLConnection.HTTP_MOVED_PERM
                        || responseCode == HttpURLConnection.HTTP_MOVED_TEMP
                        || responseCode == HttpURLConnection.HTTP_SEE_OTHER
                        || responseCode == 307
                        || responseCode == 308) {
                    String newUrl = connection.getHeaderField("Location");
                    if (newUrl == null || newUrl.isBlank()) {
                        throw new IllegalStateException("Redirect with empty Location header");
                    }
                    if (newUrl.startsWith("/")) {
                        newUrl = uri.resolve(newUrl).toString();
                    }
                    currentUrl = newUrl;
                    connection.disconnect();
                    redirectCount++;
                } else if (responseCode == HttpURLConnection.HTTP_OK) {
                    break;
                } else {
                    throw new IllegalStateException("HTTP " + responseCode + " - " + connection.getResponseMessage());
                }
            }

            if (redirectCount >= MAX_REDIRECTS) {
                throw new IllegalStateException("Too many redirects");
            }

            long contentLength = connection.getContentLengthLong();
            inputStream = connection.getInputStream();
            outputStream = new FileOutputStream(tempFile.toFile());

            item.setStatus(ExtensionItem_littlespidy.Status.DOWNLOADING);

            byte[] buffer = new byte[BUFFER_SIZE];
            long bytesReadTotal = 0;
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) != -1) {
                if (isCancelled.get() || Thread.currentThread().isInterrupted()) {
                    item.setStatus(ExtensionItem_littlespidy.Status.CANCELLED);
                    item.setStatusMessage("Cancelled");
                    notifyItemFailed(item, "Cancelled by user");
                    Files.deleteIfExists(tempFile);
                    return false;
                }

                outputStream.write(buffer, 0, bytesRead);
                bytesReadTotal += bytesRead;

                if (contentLength > 0) {
                    int percent = (int) ((bytesReadTotal * 100) / contentLength);
                    item.setProgressPercent(percent);
                    item.setStatusMessage("Downloading " + percent + "%");
                    notifyItemProgress(item, percent, bytesReadTotal, contentLength);
                }
            }

            outputStream.flush();
            outputStream.close();
            outputStream = null;

            inputStream.close();
            inputStream = null;

            Files.move(tempFile, targetFile, StandardCopyOption.REPLACE_EXISTING);

            item.setProgressPercent(100);
            item.setStatus(ExtensionItem_littlespidy.Status.COMPLETED);
            item.setStatusMessage("Completed (" + formatFileSize(bytesReadTotal) + ")");
            notifyItemCompleted(item, targetFile);
            log("Successfully saved " + item.getJarFileName() + " (" + formatFileSize(bytesReadTotal) + ")", false);
            return true;

        } catch (Exception e) {
            // Check for local repository fallback in case network is offline
            Path localFallback = findLocalJarFallback(item.getJarFileName());
            if (localFallback != null && Files.exists(localFallback)) {
                try {
                    Files.copy(localFallback, targetFile, StandardCopyOption.REPLACE_EXISTING);
                    long size = Files.size(targetFile);
                    item.setProgressPercent(100);
                    item.setStatus(ExtensionItem_littlespidy.Status.COMPLETED);
                    item.setStatusMessage("Completed (" + formatFileSize(size) + " - local)");
                    notifyItemCompleted(item, targetFile);
                    log("Loaded from local repository: " + item.getJarFileName(), false);
                    return true;
                } catch (Exception copyEx) {
                    // fall through
                }
            }

            item.setStatus(ExtensionItem_littlespidy.Status.FAILED);
            item.setStatusMessage("Failed: " + e.getMessage());
            notifyItemFailed(item, e.getMessage());
            log("Failed downloading " + item.getJarFileName() + ": " + e.getMessage(), true);
            try {
                Files.deleteIfExists(tempFile);
            } catch (Exception ignored) {
            }
            return false;
        } finally {
            if (inputStream != null) {
                try { inputStream.close(); } catch (Exception ignored) {}
            }
            if (outputStream != null) {
                try { outputStream.close(); } catch (Exception ignored) {}
            }
            if (connection != null) {
                try { connection.disconnect(); } catch (Exception ignored) {}
            }
        }
    }

    private Path findLocalJarFallback(String jarFileName) {
        String currentDir = System.getProperty("user.dir", ".");
        Path repoRoot = Paths.get(currentDir).getParent();
        if (repoRoot != null && Files.exists(repoRoot)) {
            try (var stream = Files.walk(repoRoot, 4)) {
                return stream.filter(p -> p.getFileName().toString().equals(jarFileName)
                                && p.toString().contains("build/libs"))
                        .findFirst()
                        .orElse(null);
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    public boolean openFolderInDesktop(Path directory) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                Desktop.getDesktop().open(directory.toFile());
                return true;
            } else {
                // Linux fallback
                Runtime.getRuntime().exec(new String[]{"xdg-open", directory.toAbsolutePath().toString()});
                return true;
            }
        } catch (Exception e) {
            log("Could not open file manager: " + e.getMessage(), true);
            return false;
        }
    }

    private String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        char pre = "KMGTPE".charAt(exp - 1);
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), pre);
    }

    private void log(String message, boolean isError) {
        for (DownloadListener listener : listeners) {
            listener.onLog(message, isError);
        }
        if (api != null) {
            if (isError) {
                api.logging().logToError("[QuickHelper Downloader] " + message);
            } else {
                api.logging().logToOutput("[QuickHelper Downloader] " + message);
            }
        }
    }

    private void notifyItemStarted(ExtensionItem_littlespidy item) {
        for (DownloadListener l : listeners) l.onItemStarted(item);
    }

    private void notifyItemProgress(ExtensionItem_littlespidy item, int percent, long bytesRead, long totalBytes) {
        for (DownloadListener l : listeners) l.onItemProgress(item, percent, bytesRead, totalBytes);
    }

    private void notifyItemCompleted(ExtensionItem_littlespidy item, Path savedPath) {
        for (DownloadListener l : listeners) l.onItemCompleted(item, savedPath);
    }

    private void notifyItemFailed(ExtensionItem_littlespidy item, String errorMessage) {
        for (DownloadListener l : listeners) l.onItemFailed(item, errorMessage);
    }

    private void notifyBatchProgress(int completedCount, int totalCount, ExtensionItem_littlespidy currentItem) {
        for (DownloadListener l : listeners) l.onBatchProgress(completedCount, totalCount, currentItem);
    }

    private void notifyBatchCompleted(int successCount, int failedCount, Path destinationDir) {
        for (DownloadListener l : listeners) l.onBatchCompleted(successCount, failedCount, destinationDir);
    }

    public void shutdown() {
        cancelDownloads();
        executor.shutdownNow();
    }
}
