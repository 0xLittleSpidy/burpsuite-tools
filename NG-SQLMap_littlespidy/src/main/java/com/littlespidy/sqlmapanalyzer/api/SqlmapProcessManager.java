// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.api;

import com.littlespidy.sqlmapanalyzer.util.OSUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
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

        String rawScript = config.getApiScriptPath();
        String cleanedScript = OSUtils.cleanPath(rawScript);

        if (cleanedScript.isBlank() || !new File(cleanedScript).exists()) {
            if (logConsumer != null) {
                logConsumer.accept("Error: sqlmapapi.py script not found at '" + rawScript + "'. Please specify a valid path in API Settings.");
            }
            return false;
        }

        String pythonBin = config.getPythonPath();
        if (pythonBin == null || pythonBin.isBlank()) {
            pythonBin = OSUtils.getDefaultPythonBinary();
        } else {
            pythonBin = OSUtils.cleanPath(pythonBin);
        }

        String username = config.getUsername();
        if (username == null || username.isBlank()) {
            username = "admin";
            config.setUsername(username);
        }

        String password = config.getPassword();
        if (password == null || password.isBlank()) {
            password = "sqlmapapi_pass";
            config.setPassword(password);
        }

        List<String> cmd = new ArrayList<>();
        cmd.add(pythonBin);
        cmd.add(cleanedScript);
        cmd.add("-s");
        cmd.add("-H");
        cmd.add(config.getHost());
        cmd.add("-p");
        cmd.add(String.valueOf(config.getPort()));
        cmd.add("--username");
        cmd.add(username);
        cmd.add("--password");
        cmd.add(password);

        try {
            if (logConsumer != null) {
                logConsumer.accept("[API SERVER] Launching: " + pythonBin + " " + cleanedScript + " -s -H "
                        + config.getHost() + " -p " + config.getPort() + " --username " + username + " --password ********");
            }

            ProcessBuilder pb = new ProcessBuilder(cmd);
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
