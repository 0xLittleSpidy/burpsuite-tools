// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Dual-backend AI security analysis engine supporting both:
 * <ol>
 *   <li><b>Local LLM REST APIs:</b> Direct HTTP integration with Ollama (localhost:11434),
 *       LM Studio (localhost:1234), LocalAI, or any OpenAI-compatible server.</li>
 *   <li><b>Antigravity CLI (agy):</b> Subprocess execution using the local agy agent
 *       with multi-file workspace directories and real-time output streaming.</li>
 * </ol>
 *
 * @author littlespidy
 */
public class AiSecurityEngine {

    private final HttpClient httpClient;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private volatile Process currentProcess = null;
    private volatile CompletableFuture<?> currentHttpFuture = null;

    public AiSecurityEngine() {
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    public boolean isRunning() {
        return isRunning.get();
    }

    public void stop() {
        isRunning.set(false);
        if (currentHttpFuture != null && !currentHttpFuture.isDone()) {
            currentHttpFuture.cancel(true);
        }
        if (currentProcess != null && currentProcess.isAlive()) {
            currentProcess.destroyForcibly();
        }
    }

    // ── Backend 1: Local LLM REST API (Ollama / LM Studio) ───────────────────

    public void analyzeWithLocalLlm(
        String endpointUrl,
        String modelName,
        String systemPrompt,
        String userPrompt,
        String codeContent,
        Consumer<String> progressListener,
        Consumer<String> resultListener,
        Consumer<Throwable> errorListener
    ) {
        if (!isRunning.compareAndSet(false, true)) {
            errorListener.accept(new IllegalStateException("An AI analysis is already running."));
            return;
        }

        progressListener.accept("Preparing request for Local LLM (" + modelName + ")...");

        CompletableFuture.runAsync(() -> {
            try {
                String fullUserContent = userPrompt + "\n\n```javascript\n" + codeContent + "\n```";

                // Build JSON payload
                String jsonPayload = String.format(
                    "{\"model\":\"%s\",\"messages\":[" +
                    "{\"role\":\"system\",\"content\":%s}," +
                    "{\"role\":\"user\",\"content\":%s}" +
                    "],\"temperature\":0.2}",
                    escapeJson(modelName),
                    quoteJson(systemPrompt),
                    quoteJson(fullUserContent)
                );

                String targetUrl = endpointUrl;
                if (!targetUrl.endsWith("/chat/completions") && !targetUrl.endsWith("/generate")) {
                    if (targetUrl.endsWith("/")) {
                        targetUrl += "v1/chat/completions";
                    } else {
                        targetUrl += "/v1/chat/completions";
                    }
                }

                progressListener.accept("Connecting to Local LLM at " + targetUrl + "...");

                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofMinutes(5))
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload, StandardCharsets.UTF_8))
                    .build();

                currentHttpFuture = httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                    .thenAccept(response -> {
                        isRunning.set(false);
                        int status = response.statusCode();
                        String body = response.body();

                        if (status >= 200 && status < 300) {
                            String extracted = extractContentFromOpenAiJson(body);
                            resultListener.accept(extracted != null ? extracted : body);
                        } else {
                            errorListener.accept(new IOException("Local LLM returned HTTP " + status + ":\n" + body));
                        }
                    })
                    .exceptionally(ex -> {
                        isRunning.set(false);
                        if (!isRunning.get()) {
                            // User stopped
                            progressListener.accept("Analysis cancelled by user.");
                        } else {
                            errorListener.accept(new IOException("Connection failed to " + endpointUrl +
                                ".\n\nMake sure your local LLM server is running:\n" +
                                "• Ollama: 'ollama serve' or 'ollama run " + modelName + "'\n" +
                                "• LM Studio: Start Local Server on port 1234", ex));
                        }
                        return null;
                    });

            } catch (Exception e) {
                isRunning.set(false);
                errorListener.accept(e);
            }
        });
    }

    // ── Backend 2: Antigravity CLI (agy) ─────────────────────────────────────

    public void analyzeWithAntigravityCli(
        String agyBinaryPath,
        String customPrompt,
        String codeContent,
        String targetFileName,
        Consumer<String> outputChunkListener,
        Consumer<Integer> completionListener,
        Consumer<Throwable> errorListener
    ) {
        if (!isRunning.compareAndSet(false, true)) {
            errorListener.accept(new IllegalStateException("An AI analysis is already running."));
            return;
        }

        CompletableFuture.runAsync(() -> {
            try {
                // 1. Create a dedicated analysis workspace
                Path tempDir = Files.createTempDirectory("agy_js_audit_");
                Path jsFile = tempDir.resolve(targetFileName != null && !targetFileName.isEmpty() ? targetFileName : "source.js");
                Files.writeString(jsFile, codeContent, StandardCharsets.UTF_8);

                // 2. Resolve agy binary
                String resolvedAgy = resolveAgyPath(agyBinaryPath);
                if (resolvedAgy == null) {
                    isRunning.set(false);
                    errorListener.accept(new FileNotFoundException(
                        "Antigravity CLI executable 'agy' not found!\n" +
                        "Checked: " + agyBinaryPath + ", ~/.local/bin/agy, /usr/bin/agy.\n" +
                        "Please verify Antigravity is installed and accessible."
                    ));
                    return;
                }

                outputChunkListener.accept("⚡ Initializing Antigravity CLI (" + resolvedAgy + ")...\n");
                outputChunkListener.accept("📁 Workspace created: " + tempDir.toAbsolutePath() + "\n");
                outputChunkListener.accept("📄 Target source written: " + jsFile.getFileName() + " (" + codeContent.length() + " chars)\n\n");

                // 3. Build command
                String promptText = (customPrompt != null && !customPrompt.trim().isEmpty())
                    ? customPrompt
                    : "Perform a rigorous client-side security review of the JavaScript file '" + jsFile.getFileName() + "'. " +
                      "Examine DOM XSS sinks, insecure postMessage handling, client-side authentication/authorization bypasses, " +
                      "hardcoded credentials/tokens, and sensitive hidden API endpoints. Provide line numbers and remediation advice.";

                ProcessBuilder pb = new ProcessBuilder(
                    resolvedAgy,
                    "--add-dir", tempDir.toAbsolutePath().toString(),
                    "--print",
                    promptText
                );

                pb.directory(tempDir.toFile());
                pb.redirectErrorStream(true);

                currentProcess = pb.start();

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(currentProcess.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (!isRunning.get()) break;
                        outputChunkListener.accept(line + "\n");
                    }
                }

                int exitCode = currentProcess.waitFor();
                isRunning.set(false);
                completionListener.accept(exitCode);

            } catch (Exception e) {
                isRunning.set(false);
                errorListener.accept(e);
            }
        });
    }

    public static String resolveAgyPath(String preferredPath) {
        if (preferredPath != null && !preferredPath.trim().isEmpty()) {
            File f = new File(preferredPath.trim());
            if (f.exists() && f.canExecute()) return f.getAbsolutePath();
        }

        String[] defaults = {
            "/home/littlespidy/.local/bin/agy",
            "/usr/local/bin/agy",
            "/usr/bin/agy",
            System.getProperty("user.home") + "/.local/bin/agy"
        };

        for (String path : defaults) {
            File f = new File(path);
            if (f.exists() && f.canExecute()) {
                return f.getAbsolutePath();
            }
        }

        return "agy"; // fallback to PATH
    }

    // ── JSON Utilities ───────────────────────────────────────────────────────

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String quoteJson(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    private static String extractContentFromOpenAiJson(String json) {
        if (json == null) return null;

        // Extract "content":"..." from choices array
        int contentIdx = json.indexOf("\"content\":");
        if (contentIdx == -1) {
            // Check for Ollama native format: "response":"..."
            contentIdx = json.indexOf("\"response\":");
            if (contentIdx == -1) return json;
        }

        int startQuote = json.indexOf('"', contentIdx + 10);
        if (startQuote == -1) return json;

        StringBuilder sb = new StringBuilder();
        boolean escape = false;
        for (int i = startQuote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escape) {
                switch (c) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case 'u' -> {
                        if (i + 4 < json.length()) {
                            try {
                                int codePoint = Integer.parseInt(json.substring(i + 1, i + 5), 16);
                                sb.append((char) codePoint);
                                i += 4;
                            } catch (Exception ignored) {
                                sb.append(c);
                            }
                        } else {
                            sb.append(c);
                        }
                    }
                    default -> sb.append(c);
                }
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (c == '"') {
                break; // end of content string
            } else {
                sb.append(c);
            }
        }

        return sb.toString();
    }

    /**
     * Discovers installed/loaded models from the local LLM endpoint.
     * Supports both Ollama (/api/tags) and LM Studio / vLLM / OpenAI (/v1/models).
     *
     * @param endpointUrl Base endpoint URL, e.g. "http://127.0.0.1:11434"
     * @return List of discovered model identifier strings.
     */
    public List<String> fetchInstalledModels(String endpointUrl) {
        if (endpointUrl == null || endpointUrl.isBlank()) {
            return Collections.emptyList();
        }

        String base = endpointUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }

        List<String> models = new ArrayList<>();

        // 1. Try Ollama native endpoint: /api/tags
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(base + "/api/tags"))
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(4))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                String body = response.body();
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
                while (m.find()) {
                    String name = m.group(1);
                    if (!models.contains(name)) {
                        models.add(name);
                    }
                }
            }
        } catch (Exception ignored) {
            // Fall through to /v1/models
        }

        // 2. Try OpenAI-compatible endpoint: /v1/models (LM Studio, LocalAI, vLLM, Ollama)
        if (models.isEmpty()) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(base + "/v1/models"))
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(4))
                    .GET()
                    .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    String body = response.body();
                    java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
                    while (m.find()) {
                        String id = m.group(1);
                        if (!models.contains(id)) {
                            models.add(id);
                        }
                    }
                }
            } catch (Exception ignored) {}
        }

        return models;
    }
}
