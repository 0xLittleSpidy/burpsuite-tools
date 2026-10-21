// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.runner;

import com.littlespidy.sqlmapanalyzer.api.SqlmapApiClient;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapFinding;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapLogEntry;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapScanStatus;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Coordinates scan launching, asynchronous polling, log streaming, and cancellation.
 * Plain ASCII text only.
 */
public class ScanTaskManager {

    public interface ScanUpdateListener {
        void onLogsUpdated(ScanExecutionRecord record, List<SqlmapLogEntry> newLogs);
        void onStatusChanged(ScanExecutionRecord record, String status);
        void onFindingsUpdated(ScanExecutionRecord record, List<SqlmapFinding> findings);
        void onScanComplete(ScanExecutionRecord record);
        void onScanError(ScanExecutionRecord record, String errorMessage);
    }

    private final SqlmapApiClient apiClient;
    private final ExecutorService scanExecutor;
    private final Map<String, Future<?>> activePollers = new ConcurrentHashMap<>();
    private final Set<String> cancelledRecordIds = ConcurrentHashMap.newKeySet();

    public ScanTaskManager(SqlmapApiClient apiClient) {
        this.apiClient = apiClient;
        this.scanExecutor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "sqlmap-scan-task");
            t.setDaemon(true);
            return t;
        });
    }

    public SqlmapApiClient getApiClient() {
        return apiClient;
    }

    /**
     * Starts a scan execution run asynchronously.
     */
    public void startScan(ScanExecutionRecord record, ScanUpdateListener listener) {
        if (record == null) return;

        cancelledRecordIds.remove(record.getRecordId());
        record.setCancelled(false);

        Future<?> future = scanExecutor.submit(() -> {
            try {
                if (listener != null) listener.onStatusChanged(record, "INITIALIZING");

                // 1. Create new task
                String taskId = apiClient.createNewTask();
                if (taskId == null || taskId.isBlank()) {
                    record.setStatus("ERROR");
                    if (listener != null) {
                        listener.onStatusChanged(record, "ERROR");
                        listener.onScanError(record, "Failed to create SQLMap task. Ensure the SQLMap API server is running.");
                    }
                    return;
                }
                record.setTaskId(taskId);

                if (record.isCancelled() || cancelledRecordIds.contains(record.getRecordId())) {
                    apiClient.stopScan(taskId);
                    record.setStatus("CANCELLED");
                    if (listener != null) listener.onStatusChanged(record, "CANCELLED");
                    return;
                }

                // 2. Set options
                boolean optionsSet = apiClient.setOptions(taskId, record.getOptions());
                if (!optionsSet) {
                    record.setStatus("ERROR");
                    if (listener != null) {
                        listener.onStatusChanged(record, "ERROR");
                        listener.onScanError(record, "Failed to apply options on SQLMap task ID " + taskId);
                    }
                    return;
                }

                if (record.isCancelled() || cancelledRecordIds.contains(record.getRecordId())) {
                    apiClient.stopScan(taskId);
                    record.setStatus("CANCELLED");
                    if (listener != null) listener.onStatusChanged(record, "CANCELLED");
                    return;
                }

                // 3. Start scan
                boolean started = apiClient.startScan(taskId, record.getOptions().getUrl());
                if (!started) {
                    record.setStatus("ERROR");
                    if (listener != null) {
                        listener.onStatusChanged(record, "ERROR");
                        listener.onScanError(record, "Failed to start SQLMap scan on task ID " + taskId);
                    }
                    return;
                }

                record.setStatus("RUNNING");
                if (listener != null) listener.onStatusChanged(record, "RUNNING");

                // 4. Polling loop
                int lastLogCount = 0;
                while (!Thread.currentThread().isInterrupted()) {
                    Thread.sleep(1000);

                    if (record.isCancelled() || cancelledRecordIds.contains(record.getRecordId())) {
                        record.setStatus("CANCELLED");
                        if (listener != null) {
                            listener.onStatusChanged(record, "CANCELLED");
                            listener.onScanComplete(record);
                        }
                        break;
                    }

                    // Poll logs
                    List<SqlmapLogEntry> logs = apiClient.getScanLogs(taskId);
                    if (logs != null && logs.size() > lastLogCount) {
                        record.setLogs(logs);
                        lastLogCount = logs.size();
                        if (listener != null) {
                            listener.onLogsUpdated(record, logs);
                        }
                    }

                    // Poll status
                    SqlmapScanStatus status = apiClient.getScanStatus(taskId);
                    if (status.isTerminated()) {
                        if (record.isCancelled() || cancelledRecordIds.contains(record.getRecordId())) {
                            record.setStatus("CANCELLED");
                            if (listener != null) {
                                listener.onStatusChanged(record, "CANCELLED");
                                listener.onScanComplete(record);
                            }
                            break;
                        }

                        // Gather findings
                        List<SqlmapFinding> findings = apiClient.getScanData(taskId);
                        record.setFindings(findings);
                        if (listener != null) {
                            listener.onFindingsUpdated(record, findings);
                        }

                        if (record.isVulnerable()) {
                            record.setStatus("VULNERABLE");
                        } else {
                            record.setStatus("COMPLETED");
                        }

                        if (listener != null) {
                            listener.onStatusChanged(record, record.getStatus());
                            listener.onScanComplete(record);
                        }
                        break;
                    }
                }
            } catch (InterruptedException e) {
                record.setStatus("CANCELLED");
                if (listener != null) {
                    listener.onStatusChanged(record, "CANCELLED");
                    listener.onScanComplete(record);
                }
            } catch (Exception e) {
                if (record.isCancelled() || cancelledRecordIds.contains(record.getRecordId())) {
                    record.setStatus("CANCELLED");
                    if (listener != null) {
                        listener.onStatusChanged(record, "CANCELLED");
                        listener.onScanComplete(record);
                    }
                } else {
                    record.setStatus("ERROR");
                    if (listener != null) {
                        listener.onStatusChanged(record, "ERROR");
                        listener.onScanError(record, "Scan exception: " + e.getMessage());
                    }
                }
            } finally {
                activePollers.remove(record.getRecordId());
            }
        });

        activePollers.put(record.getRecordId(), future);
    }

    /**
     * Cancels an active scan task immediately.
     */
    public void cancelScan(ScanExecutionRecord record) {
        if (record == null) return;
        cancelledRecordIds.add(record.getRecordId());
        record.setCancelled(true);
        record.setStatus("CANCELLED");
        record.addLog(new SqlmapLogEntry("INFO", "", "Scan cancelled by user."));

        String taskId = record.getTaskId();
        if (taskId != null && !taskId.isBlank()) {
            try {
                apiClient.stopScan(taskId);
            } catch (Exception ignored) {}
        }
        Future<?> future = activePollers.remove(record.getRecordId());
        if (future != null) {
            future.cancel(true);
        }
    }

    public boolean isScanning(ScanExecutionRecord record) {
        if (record == null) return false;
        return activePollers.containsKey(record.getRecordId()) && !record.isCancelled();
    }

    public void shutdown() {
        for (Future<?> f : activePollers.values()) {
            f.cancel(true);
        }
        activePollers.clear();
        cancelledRecordIds.clear();
        scanExecutor.shutdownNow();
    }
}
