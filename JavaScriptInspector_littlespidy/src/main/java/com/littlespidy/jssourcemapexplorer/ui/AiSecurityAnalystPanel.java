// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.jssourcemapexplorer.engine.AiSecurityEngine;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Interactive AI Security Analyst panel enabling automated vulnerability audits
 * of JavaScript files and reconstructed source code using both:
 * <ul>
 *   <li><b>Local LLM:</b> Direct REST API connection to Ollama (default localhost:11434)
 *       or LM Studio with zero data leaving the local system.</li>
 *   <li><b>Antigravity CLI:</b> Invocation of the local agy agent with automated workspace
 *       provisioning and real-time streaming analysis.</li>
 * </ul>
 *
 * @author littlespidy
 */
public class AiSecurityAnalystPanel extends JPanel {

    private final MontoyaApi api;
    private final AiSecurityEngine engine = new AiSecurityEngine();

    // ── Target State ──
    private String currentTargetName = "None selected";
    private String currentTargetCode = "";

    // ── Header Controls ──
    private final JLabel targetLabel = new JLabel("Target: No JavaScript file selected");
    private final JComboBox<String> backendSelector = new JComboBox<>(new String[]{
        "Local LLM (Ollama / LM Studio)",
        "Antigravity CLI (agy)"
    });

    // Local LLM Fields
    private final JTextField endpointField = new JTextField("http://127.0.0.1:11434", 16);
    private final JComboBox<String> modelSelector = new JComboBox<>(new String[]{
        "qwen2.5-coder:latest",
        "qwen2.5-coder:7b",
        "deepseek-coder:latest",
        "llama3.3:latest",
        "codellama:latest",
        "mistral:latest"
    });
    private final JButton fetchModelsBtn = new JButton("🔄 Fetch Models");

    // Antigravity CLI Fields
    private final JTextField agyPathField = new JTextField(AiSecurityEngine.resolveAgyPath(null), 20);

    // Audit Preset Prompts
    private final JComboBox<String> presetSelector = new JComboBox<>(new String[]{
        "Full Security Audit (DOM XSS, Secrets, Auth, Endpoints)",
        "DOM XSS & Sink Vulnerabilities Focus",
        "API Routes & Client-Side Auth Bypass Focus",
        "Secrets & Cloud Credentials Exposure Focus",
        "Custom Prompt (Edit in prompt box)"
    });

    // ── Action Buttons ──
    private final JButton runBtn = new JButton("⚡ Run AI Analysis");
    private final JButton stopBtn = new JButton("⏹ Stop");
    private final JButton exportBtn = new JButton("Export Report (MD)");
    private final JButton copyBtn = new JButton("Copy Analysis");
    private final JButton clearBtn = new JButton("Clear");

    // ── Center Areas ──
    private final JTextArea promptArea = new JTextArea(4, 30);
    private final JTextArea codePreviewArea = new JTextArea();
    private final JTextArea analysisOutputArea = new JTextArea();
    private final JLabel statusLabel = new JLabel("Status: Ready. Select a JavaScript file and click Run AI Analysis.");

    // Dynamic panels
    private final JPanel localLlmConfigPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
    private final JPanel agyConfigPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

    public AiSecurityAnalystPanel(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        modelSelector.setEditable(true);

        // ── Top Header Toolbar ──
        JPanel headerPanel = new JPanel(new BorderLayout(5, 5));

        // 1. Target Banner
        JPanel targetBanner = new JPanel(new BorderLayout(5, 5));
        targetBanner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createEtchedBorder(),
            BorderFactory.createEmptyBorder(6, 8, 6, 8)
        ));
        targetLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        targetBanner.add(targetLabel, BorderLayout.CENTER);

        JButton selectSnippetBtn = new JButton("Load From Clipboard");
        selectSnippetBtn.addActionListener(e -> loadCodeFromClipboard());
        targetBanner.add(selectSnippetBtn, BorderLayout.EAST);

        // 2. Engine Configuration Toolbar
        JPanel configBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JLabel backendLbl = new JLabel("Backend:");
        backendLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        configBar.add(backendLbl);
        configBar.add(backendSelector);

        // Local LLM Panel
        localLlmConfigPanel.add(new JLabel("Endpoint:"));
        localLlmConfigPanel.add(endpointField);
        localLlmConfigPanel.add(new JLabel("Model:"));
        localLlmConfigPanel.add(modelSelector);
        fetchModelsBtn.setToolTipText("Discover installed models from Ollama (/api/tags) or LM Studio (/v1/models)");
        fetchModelsBtn.addActionListener(e -> fetchInstalledModelsAsync(true));
        localLlmConfigPanel.add(fetchModelsBtn);
        configBar.add(localLlmConfigPanel);

        // AGY Config Panel
        agyConfigPanel.add(new JLabel("agy Binary:"));
        agyConfigPanel.add(agyPathField);
        agyConfigPanel.setVisible(false);
        configBar.add(agyConfigPanel);

        backendSelector.addActionListener(e -> {
            boolean isLlm = backendSelector.getSelectedIndex() == 0;
            localLlmConfigPanel.setVisible(isLlm);
            agyConfigPanel.setVisible(!isLlm);
            revalidate();
            repaint();
        });

        // 3. Preset & Actions Toolbar
        JPanel actionsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JLabel presetLbl = new JLabel("Audit Focus:");
        presetLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        actionsBar.add(presetLbl);
        actionsBar.add(presetSelector);
        presetSelector.addActionListener(e -> updatePromptFromPreset());

        runBtn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        runBtn.setBackground(new Color(235, 245, 255));
        runBtn.addActionListener(e -> startAnalysis());
        actionsBar.add(runBtn);

        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopAnalysis());
        actionsBar.add(stopBtn);

        actionsBar.add(new JSeparator(SwingConstants.VERTICAL));

        exportBtn.addActionListener(e -> exportReport());
        actionsBar.add(exportBtn);

        copyBtn.addActionListener(e -> copyAnalysisToClipboard());
        actionsBar.add(copyBtn);

        clearBtn.addActionListener(e -> clearOutput());
        actionsBar.add(clearBtn);

        JPanel topContainer = new JPanel(new BorderLayout(4, 4));
        topContainer.add(targetBanner, BorderLayout.NORTH);
        topContainer.add(configBar, BorderLayout.CENTER);
        topContainer.add(actionsBar, BorderLayout.SOUTH);

        headerPanel.add(topContainer, BorderLayout.CENTER);
        add(headerPanel, BorderLayout.NORTH);

        // ── Center Split View ──
        // Left: Prompt Editor & Target Source Code
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        leftPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Analysis Prompt & Target JavaScript",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 12)
        ));

        promptArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        updatePromptFromPreset();

        JScrollPane promptScroll = new JScrollPane(promptArea);
        promptScroll.setBorder(BorderFactory.createTitledBorder("System & Task Prompt:"));
        promptScroll.setPreferredSize(new Dimension(300, 110));

        codePreviewArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        codePreviewArea.setTabSize(4);
        codePreviewArea.setText("// Select a JavaScript file from the Workspace or click 'Load From Clipboard'");
        JScrollPane codeScroll = new JScrollPane(codePreviewArea);
        codeScroll.setBorder(BorderFactory.createTitledBorder("Target Code Preview (Editable before sending):"));

        leftPanel.add(promptScroll, BorderLayout.NORTH);
        leftPanel.add(codeScroll, BorderLayout.CENTER);

        // Right: AI Findings & Output Viewer
        JPanel rightPanel = new JPanel(new BorderLayout(5, 5));
        rightPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "AI Security Audit Findings",
            TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 12)
        ));

        analysisOutputArea.setEditable(false);
        analysisOutputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        analysisOutputArea.setLineWrap(true);
        analysisOutputArea.setWrapStyleWord(true);
        analysisOutputArea.setText("Ready for AI Security Analysis.\n\n"
            + "Supported Workflows:\n"
            + "1. Local LLM (Ollama / LM Studio): Runs directly over local HTTP. 100% offline & private.\n"
            + "2. Antigravity CLI (agy): Spawns the local agy agent with project context and live streaming.\n");

        JScrollPane outputScroll = new JScrollPane(analysisOutputArea);
        rightPanel.add(outputScroll, BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        mainSplit.setResizeWeight(0.42);

        add(mainSplit, BorderLayout.CENTER);

        // ── Bottom Status Bar ──
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        bottomBar.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        bottomBar.add(statusLabel);
        add(bottomBar, BorderLayout.SOUTH);

        // Auto-discover models from Ollama / LM Studio in background
        fetchInstalledModelsAsync(false);
    }

    // ── Public Target Ingestion ──

    public void setTargetFile(String name, String code) {
        this.currentTargetName = name != null ? name : "untitled.js";
        this.currentTargetCode = code != null ? code : "";

        targetLabel.setText(String.format("Target: %s (%,d chars | %,d lines)",
            currentTargetName, currentTargetCode.length(), currentTargetCode.split("\r?\n").length));
        codePreviewArea.setText(currentTargetCode);
        codePreviewArea.setCaretPosition(0);

        statusLabel.setText("Loaded target: " + currentTargetName + ". Click 'Run AI Analysis' to audit.");
    }

    // ── Execution Logic ──

    private void startAnalysis() {
        String code = codePreviewArea.getText().trim();
        if (code.isEmpty() || code.startsWith("// Select a JavaScript file")) {
            JOptionPane.showMessageDialog(this,
                "Please select a JavaScript file first, or paste code into the preview box.",
                "No Code Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String userPrompt = promptArea.getText().trim();
        boolean isLocalLlm = backendSelector.getSelectedIndex() == 0;

        runBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        clearOutput();

        if (isLocalLlm) {
            String endpoint = endpointField.getText().trim();
            Object selectedItem = modelSelector.isEditable() ? modelSelector.getEditor().getItem() : modelSelector.getSelectedItem();
            String model = selectedItem != null ? selectedItem.toString().trim() : "";
            if (model.isEmpty()) model = "qwen2.5-coder:latest";

            String systemPrompt = "You are an expert offensive security engineer and client-side code auditor. " +
                "Analyze the provided JavaScript for security vulnerabilities, dangerous sinks, exposed secrets, and logic flaws. " +
                "Provide detailed findings with risk severity (High/Medium/Low/Info), line numbers, root cause, and concrete remediation advice.";

            statusLabel.setText("Connecting to Local LLM at " + endpoint + " (" + model + ")...");
            appendOutput("================================================================================\n");
            appendOutput("  AI Security Audit: " + currentTargetName + "\n");
            appendOutput("  Backend: Local LLM (" + model + ") @ " + endpoint + "\n");
            appendOutput("  Time: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + "\n");
            appendOutput("================================================================================\n\n");
            appendOutput("[*] Sending request to local model...\n\n");

            long startTime = System.currentTimeMillis();

            engine.analyzeWithLocalLlm(
                endpoint, model, systemPrompt, userPrompt, code,
                msg -> SwingUtilities.invokeLater(() -> statusLabel.setText(msg)),
                result -> SwingUtilities.invokeLater(() -> {
                    long duration = System.currentTimeMillis() - startTime;
                    appendOutput(result);
                    appendOutput("\n\n--------------------------------------------------------------------------------\n");
                    appendOutput(String.format("[✓] Analysis complete in %.2f seconds.\n", duration / 1000.0));
                    statusLabel.setText("Analysis finished in " + (duration / 1000) + "s.");
                    runBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                }),
                err -> SwingUtilities.invokeLater(() -> {
                    appendOutput("\n[!] ERROR: " + err.getMessage() + "\n");
                    statusLabel.setText("Error: " + err.getMessage());
                    runBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                })
            );

        } else {
            // Antigravity CLI
            String agyPath = agyPathField.getText().trim();
            statusLabel.setText("Spawning Antigravity CLI (" + agyPath + ")...");

            appendOutput("================================================================================\n");
            appendOutput("  AI Security Audit: " + currentTargetName + "\n");
            appendOutput("  Backend: Antigravity CLI (agy)\n");
            appendOutput("  Time: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + "\n");
            appendOutput("================================================================================\n\n");

            long startTime = System.currentTimeMillis();

            engine.analyzeWithAntigravityCli(
                agyPath, userPrompt, code, currentTargetName,
                chunk -> SwingUtilities.invokeLater(() -> appendOutput(chunk)),
                exitCode -> SwingUtilities.invokeLater(() -> {
                    long duration = System.currentTimeMillis() - startTime;
                    appendOutput("\n--------------------------------------------------------------------------------\n");
                    appendOutput(String.format("[✓] Antigravity CLI process exited with code %d (in %.2fs).\n", exitCode, duration / 1000.0));
                    statusLabel.setText("Antigravity process complete (exit " + exitCode + ").");
                    runBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                }),
                err -> SwingUtilities.invokeLater(() -> {
                    appendOutput("\n[!] CLI ERROR: " + err.getMessage() + "\n");
                    statusLabel.setText("CLI Error: " + err.getMessage());
                    runBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                })
            );
        }
    }

    private void stopAnalysis() {
        engine.stop();
        statusLabel.setText("Analysis aborted by user.");
        appendOutput("\n\n[!] Analysis stopped by user.\n");
        runBtn.setEnabled(true);
        stopBtn.setEnabled(false);
    }

    private void updatePromptFromPreset() {
        int idx = presetSelector.getSelectedIndex();
        String prompt = switch (idx) {
            case 0 -> "Perform a comprehensive security audit of this JavaScript code. Identify all:\n" +
                      "1. DOM XSS sinks (innerHTML, eval, document.write, dangerouslySetInnerHTML, v-html)\n" +
                      "2. Insecure postMessage handlers (missing/wildcard event.origin checks)\n" +
                      "3. Hardcoded secret keys, JWT tokens, AWS keys, or private API credentials\n" +
                      "4. Client-side authentication and role-check bypass vulnerabilities\n" +
                      "5. Hidden administrative endpoints, debug parameters, or developer toggles\n" +
                      "Structure your report by severity with line numbers, attack payloads, and fixes.";
            case 1 -> "Perform a deep DOM-based Cross-Site Scripting (DOM XSS) code review. Trace all sources (location.search, location.hash, document.referrer, postMessage) into execution sinks (eval, Function, setTimeout, innerHTML, srcdoc). Detail exploit scenarios and sanitization recommendations.";
            case 2 -> "Extract and analyze all internal API routes, microservice endpoints, and client-side privilege checks in this file. Highlight any authorization logic performed solely in client JavaScript that can be bypassed.";
            case 3 -> "Inspect this JavaScript file specifically for hardcoded secrets, API tokens, cloud storage bucket names, private keys, database connection strings, and exposed staging/debug credentials.";
            default -> promptArea.getText();
        };
        promptArea.setText(prompt);
        promptArea.setCaretPosition(0);
    }

    private void loadCodeFromClipboard() {
        try {
            String data = (String) Toolkit.getDefaultToolkit().getSystemClipboard()
                .getData(java.awt.datatransfer.DataFlavor.stringFlavor);
            if (data != null && !data.trim().isEmpty()) {
                setTargetFile("Clipboard_Snippet.js", data);
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to paste from clipboard: " + ex.getMessage(), "Clipboard Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportReport() {
        String text = analysisOutputArea.getText().trim();
        if (text.isEmpty() || text.startsWith("Ready for AI")) {
            JOptionPane.showMessageDialog(this, "No audit findings available to export.", "Export Report", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save AI Security Report As");
        String defaultName = "AI_Security_Audit_" + currentTargetName.replaceAll("[^a-zA-Z0-9.-]", "_") + ".md";
        chooser.setSelectedFile(new File(defaultName));

        int result = chooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File target = chooser.getSelectedFile();
            try {
                Files.writeString(target.toPath(), text, StandardCharsets.UTF_8);
                JOptionPane.showMessageDialog(this, "Saved audit report to:\n" + target.getAbsolutePath(), "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error writing file: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void copyAnalysisToClipboard() {
        String text = analysisOutputArea.getText();
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
            JOptionPane.showMessageDialog(this, "Copied analysis output to clipboard!", "Copied", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void clearOutput() {
        analysisOutputArea.setText("");
    }

    private void appendOutput(String text) {
        analysisOutputArea.append(text);
        analysisOutputArea.setCaretPosition(analysisOutputArea.getDocument().getLength());
    }

    /**
     * Discovers installed models from Ollama or LM Studio asynchronously.
     * Updates the model selector dropdown and selects the best matching model.
     *
     * @param userInitiated true if triggered by clicking the 'Fetch Models' button (shows dialogs), false on auto-load
     */
    public void fetchInstalledModelsAsync(boolean userInitiated) {
        String endpoint = endpointField.getText().trim();
        if (endpoint.isEmpty()) {
            if (userInitiated) {
                JOptionPane.showMessageDialog(this, "Please enter an Ollama or Local LLM endpoint URL first.", "Endpoint Required", JOptionPane.WARNING_MESSAGE);
            }
            return;
        }

        fetchModelsBtn.setEnabled(false);
        fetchModelsBtn.setText("🔄 Fetching...");
        statusLabel.setText("Discovering installed models from " + endpoint + "...");

        CompletableFuture.supplyAsync(() -> engine.fetchInstalledModels(endpoint))
            .thenAccept(models -> SwingUtilities.invokeLater(() -> {
                fetchModelsBtn.setEnabled(true);
                fetchModelsBtn.setText("🔄 Fetch Models");

                if (models != null && !models.isEmpty()) {
                    Object currentSelection = modelSelector.isEditable() ? modelSelector.getEditor().getItem() : modelSelector.getSelectedItem();
                    String previous = currentSelection != null ? currentSelection.toString().trim() : "";

                    modelSelector.removeAllItems();
                    for (String m : models) {
                        modelSelector.addItem(m);
                    }

                    // Attempt to restore previous selection if it's in the list
                    boolean restored = false;
                    for (String m : models) {
                        if (m.equalsIgnoreCase(previous)) {
                            modelSelector.setSelectedItem(m);
                            restored = true;
                            break;
                        }
                    }

                    // If not restored, choose a sensible coding or security default, or the first model
                    if (!restored) {
                        String preferred = null;
                        for (String m : models) {
                            String lower = m.toLowerCase();
                            if (lower.contains("coder") || lower.contains("bug") || lower.contains("security")) {
                                preferred = m;
                                break;
                            }
                        }
                        if (preferred == null) {
                            for (String m : models) {
                                String lower = m.toLowerCase();
                                if (lower.contains("qwen") || lower.contains("deepseek") || lower.contains("gemma") || lower.contains("llama")) {
                                    preferred = m;
                                    break;
                                }
                            }
                        }
                        if (preferred != null) {
                            modelSelector.setSelectedItem(preferred);
                        } else {
                            modelSelector.setSelectedIndex(0);
                        }
                    }

                    statusLabel.setText("Discovered " + models.size() + " local model(s) from " + endpoint + ".");

                    if (userInitiated) {
                        StringBuilder sb = new StringBuilder("Successfully discovered " + models.size() + " model(s):\n\n");
                        for (String m : models) {
                            sb.append("• ").append(m).append("\n");
                        }
                        JOptionPane.showMessageDialog(this, sb.toString(), "Models Discovered", JOptionPane.INFORMATION_MESSAGE);
                    }
                } else {
                    statusLabel.setText("No models discovered from " + endpoint + ". You can enter a model name manually.");
                    if (userInitiated) {
                        JOptionPane.showMessageDialog(
                            this,
                            "Could not discover any models from " + endpoint + ".\n\n"
                                + "Please check that your local server is running:\n"
                                + "• Ollama: run 'ollama serve' (default port 11434)\n"
                                + "• LM Studio: Start Local Server in LM Studio (default port 1234)\n\n"
                                + "You can also type your model name directly into the Model box.",
                            "No Models Discovered",
                            JOptionPane.WARNING_MESSAGE
                        );
                    }
                }
            }))
            .exceptionally(ex -> {
                SwingUtilities.invokeLater(() -> {
                    fetchModelsBtn.setEnabled(true);
                    fetchModelsBtn.setText("🔄 Fetch Models");
                    statusLabel.setText("Error fetching models: " + ex.getMessage());
                    if (userInitiated) {
                        JOptionPane.showMessageDialog(
                            this,
                            "Error connecting to " + endpoint + ":\n" + ex.getMessage(),
                            "Connection Error",
                            JOptionPane.ERROR_MESSAGE
                        );
                    }
                });
                return null;
            });
    }
}
