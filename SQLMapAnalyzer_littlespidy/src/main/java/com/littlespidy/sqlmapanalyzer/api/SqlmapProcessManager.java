// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.api;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Manages the lifecycle of a locally spawned sqlmapapi.py process.
 * Plain ASCII text only.
 */
public class SqlmapProcessManager {

    private Process process = null;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public synchronized boolean startServer(SqlmapApiConfig config, Consumer<String> logConsumer) {
        if (isServerRunning()) {
            return true;
        }

        String python = config.getPythonPath();
        String script = config.getApiScriptPath();

        if (script == null || script.isBlank() || !new File(script).exists()) {
            if (logConsumer != null) {
                logConsumer.accept("Error: sqlmapapi.py script not found at '" + script + "'. Please specify a valid path.");
            }
            return false;
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(
                    python,
                    script,
                    "-s",
                    "-H", config.getHost(),
                    "-p", String.valueOf(config.getPort())
            );
            pb.redirectErrorStream(true);

            process = pb.start();
            running.set(true);

            Thread logThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (logConsumer != null) {
                            logConsumer.accept("[API SERVER] " + line);
                        }
                    }
                } catch (Exception ignored) {}
                running.set(false);
            }, "sqlmapapi-stdout");
            logThread.setDaemon(true);
            logThread.start();

            // Wait brief moment to confirm it didn't immediately crash
            Thread.sleep(1000);
            return process.isAlive();
        } catch (Exception e) {
            if (logConsumer != null) {
                logConsumer.accept("Failed to start sqlmapapi.py: " + e.getMessage());
            }
            running.set(false);
            return false;
        }
    }

    public synchronized void stopServer() {
        if (process != null) {
            try {
                process.destroy();
                if (process.isAlive()) {
                    process.destroyForcibly();
                }
            } catch (Exception ignored) {}
            process = null;
        }
        running.set(false);
    }

    public boolean isServerRunning() {
        return process != null && process.isAlive();
    }
}
