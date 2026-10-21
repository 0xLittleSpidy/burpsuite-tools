// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.api;

import burp.api.montoya.MontoyaApi;

import java.io.File;
import java.io.Serializable;

/**
 * Configuration settings for connecting to or launching the SQLMap REST API server.
 * Plain ASCII text only.
 */
public class SqlmapApiConfig implements Serializable {
    private static final long serialVersionUID = 1L;

    public static final String PREF_HOST = "sqlmap_api_host_littlespidy";
    public static final String PREF_PORT = "sqlmap_api_port_littlespidy";
    public static final String PREF_PYTHON_BIN = "sqlmap_api_python_bin_littlespidy";
    public static final String PREF_API_SCRIPT = "sqlmap_api_script_path_littlespidy";

    private String host = "127.0.0.1";
    private int port = 8775;
    private String pythonPath = "python3";
    private String apiScriptPath = "";

    public SqlmapApiConfig() {
        autoDetectDefaults();
    }

    public void loadPreferences(MontoyaApi api) {
        if (api == null || api.persistence() == null || api.persistence().preferences() == null) return;
        try {
            String savedHost = api.persistence().preferences().getString(PREF_HOST);
            if (savedHost != null && !savedHost.isBlank()) this.host = savedHost.trim();

            String savedPort = api.persistence().preferences().getString(PREF_PORT);
            if (savedPort != null && !savedPort.isBlank()) {
                try { this.port = Integer.parseInt(savedPort.trim()); } catch (Exception ignored) {}
            }

            String savedPython = api.persistence().preferences().getString(PREF_PYTHON_BIN);
            if (savedPython != null && !savedPython.isBlank()) this.pythonPath = savedPython.trim();

            String savedScript = api.persistence().preferences().getString(PREF_API_SCRIPT);
            if (savedScript != null && !savedScript.isBlank()) this.apiScriptPath = savedScript.trim();
        } catch (Exception ignored) {}
    }

    public void savePreferences(MontoyaApi api) {
        if (api == null || api.persistence() == null || api.persistence().preferences() == null) return;
        try {
            api.persistence().preferences().setString(PREF_HOST, host);
            api.persistence().preferences().setString(PREF_PORT, String.valueOf(port));
            api.persistence().preferences().setString(PREF_PYTHON_BIN, pythonPath);
            api.persistence().preferences().setString(PREF_API_SCRIPT, apiScriptPath);
        } catch (Exception ignored) {}
    }

    private void autoDetectDefaults() {
        // Look for sqlmapapi.py in PATH or common directories
        String[] candidates = {
                "/usr/share/sqlmap/sqlmapapi.py",
                "/usr/local/share/sqlmap/sqlmapapi.py",
                "/opt/sqlmap/sqlmapapi.py",
                System.getProperty("user.home") + "/sqlmap/sqlmapapi.py",
                System.getProperty("user.home") + "/.local/share/sqlmap/sqlmapapi.py"
        };
        for (String c : candidates) {
            File f = new File(c);
            if (f.exists()) {
                this.apiScriptPath = f.getAbsolutePath();
                break;
            }
        }
    }

    public String getBaseUrl() {
        return "http://" + host + ":" + port;
    }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = (host != null && !host.isBlank()) ? host.trim() : "127.0.0.1"; }

    public int getPort() { return port; }
    public void setPort(int port) { this.port = (port > 0 && port <= 65535) ? port : 8775; }

    public String getPythonPath() { return pythonPath; }
    public void setPythonPath(String pythonPath) { this.pythonPath = pythonPath != null ? pythonPath.trim() : "python3"; }

    public String getApiScriptPath() { return apiScriptPath; }
    public void setApiScriptPath(String apiScriptPath) { this.apiScriptPath = apiScriptPath != null ? apiScriptPath.trim() : ""; }
}
