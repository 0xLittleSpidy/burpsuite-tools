// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.storage;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;

/**
 * Startup modal dialog displayed when Header Inspector is loaded.
 * Prompts the user to explicitly decide whether to open a previous session file,
 * create a new session file, or start a temporary in-memory session.
 */
public class SessionStartupDialog_littlespidy {

    public static final String PREF_GLOBAL_LAST_SESSION_DIR = "burp_extensions_last_session_dir_littlespidy";
    public static final String PREF_LAST_SESSION_DIR = "header_inspector_last_session_dir";

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

        String lastDir = null;
        if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
            try {
                lastDir = api.persistence().preferences().getString(PREF_GLOBAL_LAST_SESSION_DIR);
                if (lastDir == null || lastDir.isBlank()) {
                    lastDir = api.persistence().preferences().getString(PREF_LAST_SESSION_DIR);
                }
            } catch (Exception ignored) {}
        }
        File defaultDir = (lastDir != null && !lastDir.isBlank() && new File(lastDir).exists())
                ? new File(lastDir)
                : new File(System.getProperty("user.home", "."));

        Component dialogParent = parent;
        if (dialogParent == null && api != null && api.userInterface() != null && api.userInterface().swingUtils() != null) {
            try {
                dialogParent = api.userInterface().swingUtils().suiteFrame();
            } catch (Exception ignored) {}
        }

        String[] options = {"Open Previous Session", "Create New Session", "Start Temporary Session"};
        int choice = JOptionPane.showOptionDialog(
                dialogParent,
                "Select how you would like to initialize your Header Inspector session:\n\n"
                        + "- Open Previous Session: Load saved headers, methods, statuses, and security policies from disk.\n"
                        + "- Create New Session: Specify a directory to store and auto-save new session findings.\n"
                        + "- Start Temporary Session: Work in-memory without binding immediately to a file.\n",
                "Header Inspector - Session Storage Initialization",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]
        );

        if (choice == 0) {
            JFileChooser chooser = new JFileChooser(defaultDir);
            chooser.setDialogTitle("Select Existing Header Inspector Session File (*.json)");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            int fileRes = chooser.showOpenDialog(dialogParent);
            if (fileRes == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                File selected = chooser.getSelectedFile();
                rememberDirectory(api, selected.getParent());
                return new StartupResult(StartupAction.OPEN_EXISTING, selected);
            }
        } else if (choice == 1) {
            JFileChooser dirChooser = new JFileChooser(defaultDir);
            dirChooser.setDialogTitle("Select Directory For New Session File");
            dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int dirRes = dirChooser.showOpenDialog(dialogParent);
            if (dirRes == JFileChooser.APPROVE_OPTION && dirChooser.getSelectedFile() != null) {
                File chosenDir = dirChooser.getSelectedFile();
                rememberDirectory(api, chosenDir.getAbsolutePath());

                String fileName = JOptionPane.showInputDialog(
                        dialogParent,
                        "Enter filename for the new session:",
                        "header_inspector_session.json"
                );

                if (fileName != null && !fileName.isBlank()) {
                    String cleanName = fileName.trim();
                    if (!cleanName.toLowerCase().endsWith(".json")) {
                        cleanName = cleanName + ".json";
                    }
                    File newFile = new File(chosenDir, cleanName);
                    return new StartupResult(StartupAction.CREATE_NEW, newFile);
                }
            }
        }

        return new StartupResult(StartupAction.TEMPORARY, null);
    }

    public static void rememberDirectory(MontoyaApi api, String dirPath) {
        if (api != null && api.persistence() != null && api.persistence().preferences() != null && dirPath != null) {
            try {
                api.persistence().preferences().setString(PREF_GLOBAL_LAST_SESSION_DIR, dirPath);
                api.persistence().preferences().setString(PREF_LAST_SESSION_DIR, dirPath);
            } catch (Exception ignored) {}
        }
    }
}
