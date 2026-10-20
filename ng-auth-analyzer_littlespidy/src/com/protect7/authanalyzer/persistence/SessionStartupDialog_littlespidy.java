// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.persistence;

import java.awt.Component;
import java.awt.GraphicsEnvironment;
import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import burp.IBurpExtenderCallbacks;
import burp.api.montoya.MontoyaApi;

public class SessionStartupDialog_littlespidy {

	public static final String PREF_GLOBAL_LAST_SESSION_DIR = "burpsuite_extensions_last_session_dir_littlespidy";
	public static final String PREF_LAST_SESSION_DIR = "auth_analyzer_last_session_dir_littlespidy";

	public enum StartupAction {
		OPEN_EXISTING,
		CREATE_NEW,
		TEMPORARY
	}

	public static class StartupResult {
		private final StartupAction action;
		private final File sessionFile;

		public StartupResult(StartupAction action, File sessionFile) {
			this.action = action;
			this.sessionFile = sessionFile;
		}

		public StartupAction getAction() {
			return action;
		}

		public File getSessionFile() {
			return sessionFile;
		}
	}

	public static StartupResult promptUser(MontoyaApi api, IBurpExtenderCallbacks callbacks, Component parent) {
		if (GraphicsEnvironment.isHeadless() || Boolean.getBoolean("java.awt.headless")) {
			return new StartupResult(StartupAction.TEMPORARY, null);
		}

		String[] options = {"Open Existing Session", "Create New Session", "Temporary / In-Memory Session"};
		int choice = JOptionPane.showOptionDialog(
				parent,
				"Select session mode for ng-auth-analyzer_littlespidy:\n\n" +
						"- Open Existing Session: Load a previously saved session JSON file.\n" +
						"- Create New Session: Start fresh and immediately bind to a new session file.\n" +
						"- Temporary / In-Memory Session: Run in-memory without binding (can save later).",
				"ng-auth-analyzer_littlespidy - Session Startup",
				JOptionPane.DEFAULT_OPTION,
				JOptionPane.QUESTION_MESSAGE,
				null,
				options,
				options[0]
		);

		if (choice == 0) { // Open Existing
			File lastDir = getLastDirectory(api, callbacks);
			JFileChooser chooser = new JFileChooser(lastDir);
			chooser.setDialogTitle("Open Session File");
			chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
			int res = chooser.showOpenDialog(parent);
			if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
				File sel = chooser.getSelectedFile();
				rememberDirectory(api, callbacks, sel.getParent());
				return new StartupResult(StartupAction.OPEN_EXISTING, sel);
			}
		} else if (choice == 1) { // Create New
			File lastDir = getLastDirectory(api, callbacks);
			JFileChooser chooser = new JFileChooser(lastDir);
			chooser.setDialogTitle("Select Directory to Save New Session");
			chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			int res = chooser.showOpenDialog(parent);
			if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
				File dir = chooser.getSelectedFile();
				rememberDirectory(api, callbacks, dir.getAbsolutePath());
				String fileName = JOptionPane.showInputDialog(parent, "Enter session filename:", "auth_analyzer_session.json");
				if (fileName != null && !fileName.trim().isEmpty()) {
					if (!fileName.toLowerCase().endsWith(".json")) {
						fileName = fileName.trim() + ".json";
					}
					File sessionFile = new File(dir, fileName.trim());
					return new StartupResult(StartupAction.CREATE_NEW, sessionFile);
				}
			}
		}

		return new StartupResult(StartupAction.TEMPORARY, null);
	}

	public static File getLastDirectory(MontoyaApi api, IBurpExtenderCallbacks callbacks) {
		String lastDir = null;
		if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
			try {
				lastDir = api.persistence().preferences().getString(PREF_GLOBAL_LAST_SESSION_DIR);
				if (lastDir == null || lastDir.trim().isEmpty()) {
					lastDir = api.persistence().preferences().getString(PREF_LAST_SESSION_DIR);
				}
			} catch (Throwable ignored) {}
		}
		if ((lastDir == null || lastDir.trim().isEmpty()) && callbacks != null) {
			try {
				lastDir = callbacks.loadExtensionSetting(PREF_GLOBAL_LAST_SESSION_DIR);
				if (lastDir == null || lastDir.trim().isEmpty()) {
					lastDir = callbacks.loadExtensionSetting(PREF_LAST_SESSION_DIR);
				}
			} catch (Throwable ignored) {}
		}
		if (lastDir != null && !lastDir.trim().isEmpty()) {
			File d = new File(lastDir.trim());
			if (d.exists() && d.isDirectory()) return d;
		}
		return new File(System.getProperty("user.home", "."));
	}

	public static void rememberDirectory(MontoyaApi api, IBurpExtenderCallbacks callbacks, String dirPath) {
		if (dirPath == null) return;
		if (api != null && api.persistence() != null && api.persistence().preferences() != null) {
			try {
				api.persistence().preferences().setString(PREF_GLOBAL_LAST_SESSION_DIR, dirPath);
				api.persistence().preferences().setString(PREF_LAST_SESSION_DIR, dirPath);
			} catch (Throwable ignored) {}
		}
		if (callbacks != null) {
			try {
				callbacks.saveExtensionSetting(PREF_GLOBAL_LAST_SESSION_DIR, dirPath);
				callbacks.saveExtensionSetting(PREF_LAST_SESSION_DIR, dirPath);
			} catch (Throwable ignored) {}
		}
	}
}
