// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.session;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;

public class SessionStartupDialog_littlespidy {

    public enum StartupAction {
        OPEN_EXISTING,
        CREATE_NEW,
        TEMPORARY
    }

    public record StartupResult(StartupAction action, File sessionFile) {}

    public static StartupResult promptUser(MontoyaApi api, Component parent) {
        String lastDir = (api != null && api.persistence() != null)
                ? api.persistence().preferences().getString("wayback_last_session_dir")
                : null;
        File defaultDir = (lastDir != null && !lastDir.isBlank()) ? new File(lastDir) : new File(System.getProperty("user.home"));

        String[] options = {"Open Previous Session", "Create New Session", "Start Temporary Session"};
        int choice = JOptionPane.showOptionDialog(
                parent,
                "Select how you would like to initialize your wayback reconnaissance session:\n\n" +
                "- Open Previous Session: Load saved domain scans, paths, and findings from disk.\n" +
                "- Create New Session: Specify a directory to store and auto-save new session data.\n" +
                "- Start Temporary Session: Work in-memory without binding to a file immediately.\n",
                "wayback - Session Initialization",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]
        );

        if (choice == 0) {
            JFileChooser chooser = new JFileChooser(defaultDir);
            chooser.setDialogTitle("Select Existing Session File to Open");
            chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
            int fileRes = chooser.showOpenDialog(parent);
            if (fileRes == JFileChooser.APPROVE_OPTION) {
                File selected = chooser.getSelectedFile();
                if (api != null && api.persistence() != null && selected.getParent() != null) {
                    api.persistence().preferences().setString("wayback_last_session_dir", selected.getParent());
                }
                return new StartupResult(StartupAction.OPEN_EXISTING, selected);
            }
        } else if (choice == 1) {
            JFileChooser dirChooser = new JFileChooser(defaultDir);
            dirChooser.setDialogTitle("Select Directory For New Session File");
            dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int dirRes = dirChooser.showOpenDialog(parent);
            if (dirRes == JFileChooser.APPROVE_OPTION) {
                File chosenDir = dirChooser.getSelectedFile();
                if (api != null && api.persistence() != null) {
                    api.persistence().preferences().setString("wayback_last_session_dir", chosenDir.getAbsolutePath());
                }

                String fileName = JOptionPane.showInputDialog(
                        parent,
                        "Enter filename for the new session:",
                        "wayback_session.json"
                );

                if (fileName != null && !fileName.isBlank()) {
                    if (!fileName.toLowerCase().endsWith(".json")) {
                        fileName = fileName + ".json";
                    }
                    File newFile = new File(chosenDir, fileName);
                    return new StartupResult(StartupAction.CREATE_NEW, newFile);
                }
            }
        }

        return new StartupResult(StartupAction.TEMPORARY, null);
    }
}
