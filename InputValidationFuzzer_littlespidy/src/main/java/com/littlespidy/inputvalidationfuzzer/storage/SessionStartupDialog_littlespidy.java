// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.inputvalidationfuzzer.storage;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;

/**
 * Standardized Session Startup Dialog for Input Validation Fuzzer.
 * Strictly plain ASCII text with no emojis.
 */
public class SessionStartupDialog_littlespidy {

    public static final String PREF_GLOBAL_LAST_SESSION_DIR = "burp_extensions_last_session_dir_littlespidy";
    public static final String PREF_LAST_SESSION_DIR = "input_validation_fuzzer_last_session_dir_littlespidy";

    public enum StartupAction {
        OPEN_EXISTING,
        CREATE_NEW,
        TEMPORARY
    }

    public record StartupResult(StartupAction action, File sessionFile) {}

    public static StartupResult promptUser(MontoyaApi api, Component parent) {
        if (GraphicsEnvironment.isHeadless()) {
            return new StartupResult(StartupAction.TEMPORARY, null);
        }

        String[] options = {"Open Existing Session", "Create New Session", "Temporary / In-Memory Session"};
        int choice = JOptionPane.showOptionDialog(
                parent,
                "Select session mode for Input Validation Fuzzer:\n\n" +
                        "- Open Existing Session: Load a previously saved session file.\n" +
                        "- Create New Session: Start fresh and immediately bind to a new session file.\n" +
                        "- Temporary / In-Memory Session: Run without saving (can save manually later).",
                "Input Validation Fuzzer - Session Startup",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]
        );

        if (choice == 0) { // Open Existing
            File lastDir = getLastDirectory(api);
            JFileChooser chooser = new JFileChooser(lastDir);
            chooser.setDialogTitle("Open Input Validation Fuzzer Session File");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            int res = chooser.showOpenDialog(parent);
            if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                File sel = chooser.getSelectedFile();
                rememberDirectory(api, sel.getParent());
                return new StartupResult(StartupAction.OPEN_EXISTING, sel);
            }
        } else if (choice == 1) { // Create New
            File lastDir = getLastDirectory(api);
            JFileChooser chooser = new JFileChooser(lastDir);
            chooser.setDialogTitle("Select Directory to Save New Input Validation Fuzzer Session");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int res = chooser.showOpenDialog(parent);
            if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                File dir = chooser.getSelectedFile();
                rememberDirectory(api, dir.getAbsolutePath());
                String fileName = JOptionPane.showInputDialog(parent, "Enter session filename:", "input_validation_fuzzer_session.json");
                if (fileName != null && !fileName.isBlank()) {
                    if (!fileName.toLowerCase().endsWith(".json")) {
                        fileName = fileName + ".json";
                    }
                    File sessionFile = new File(dir, fileName.trim());
                    return new StartupResult(StartupAction.CREATE_NEW, sessionFile);
                }
            }
        }

        return new StartupResult(StartupAction.TEMPORARY, null);
    }

    private static File getLastDirectory(MontoyaApi api) {
        String lastDir = null;
        if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
            try {
                lastDir = api.persistence().preferences().getString(PREF_GLOBAL_LAST_SESSION_DIR);
                if (lastDir == null || lastDir.isBlank()) {
                    lastDir = api.persistence().preferences().getString(PREF_LAST_SESSION_DIR);
                }
            } catch (Exception ignored) {}
        }
        if (lastDir != null && !lastDir.isBlank()) {
            File d = new File(lastDir);
            if (d.exists() && d.isDirectory()) return d;
        }
        return new File(System.getProperty("user.home", "."));
    }

    private static void rememberDirectory(MontoyaApi api, String dirPath) {
        if (api != null && api.persistence() != null && api.persistence().preferences() != null && dirPath != null) {
            try {
                api.persistence().preferences().setString(PREF_GLOBAL_LAST_SESSION_DIR, dirPath);
                api.persistence().preferences().setString(PREF_LAST_SESSION_DIR, dirPath);
            } catch (Exception ignored) {}
        }
    }
}
