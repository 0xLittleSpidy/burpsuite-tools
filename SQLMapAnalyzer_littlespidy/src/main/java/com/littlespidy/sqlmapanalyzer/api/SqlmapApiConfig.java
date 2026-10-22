// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.api;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.sqlmapanalyzer.util.OSUtils;

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
    public static final String PREF_USERNAME = "sqlmap_api_username_littlespidy";
    public static final String PREF_PASSWORD = "sqlmap_api_password_littlespidy";

    private String host = "127.0.0.1";
    private int port = 8775;
    private String pythonPath = OSUtils.getDefaultPythonBinary();
    private String apiScriptPath = "";
    private String username = "admin";
    private String password = "sqlmapapi_pass";

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
            if (savedPython != null && !savedPython.isBlank()) {
                this.pythonPath = savedPython.trim();
            } else {
                this.pythonPath = OSUtils.getDefaultPythonBinary();
            }

            String savedScript = api.persistence().preferences().getString(PREF_API_SCRIPT);
            if (savedScript != null && !savedScript.isBlank()) {
                this.apiScriptPath = OSUtils.cleanPath(savedScript);
            } else if (this.apiScriptPath == null || this.apiScriptPath.isBlank()) {
                this.apiScriptPath = OSUtils.findSqlmapApiPath();
            }

            String savedUser = api.persistence().preferences().getString(PREF_USERNAME);
            if (savedUser != null && !savedUser.isBlank()) this.username = savedUser.trim();

            String savedPass = api.persistence().preferences().getString(PREF_PASSWORD);
            if (savedPass != null && !savedPass.isBlank()) this.password = savedPass.trim();
        } catch (Exception ignored) {}
    }

    public void savePreferences(MontoyaApi api) {
        if (api == null || api.persistence() == null || api.persistence().preferences() == null) return;
        try {
            api.persistence().preferences().setString(PREF_HOST, host);
            api.persistence().preferences().setString(PREF_PORT, String.valueOf(port));
            api.persistence().preferences().setString(PREF_PYTHON_BIN, pythonPath);
            api.persistence().preferences().setString(PREF_API_SCRIPT, apiScriptPath);
            api.persistence().preferences().setString(PREF_USERNAME, username);
            api.persistence().preferences().setString(PREF_PASSWORD, password);
        } catch (Exception ignored) {}
    }

    public void autoDetectDefaults() {
        this.pythonPath = OSUtils.getDefaultPythonBinary();
        String detected = OSUtils.findSqlmapApiPath();
        if (detected != null && !detected.isBlank()) {
            this.apiScriptPath = detected;
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
    public void setPythonPath(String pythonPath) {
        this.pythonPath = (pythonPath != null && !pythonPath.isBlank()) ? OSUtils.cleanPath(pythonPath) : OSUtils.getDefaultPythonBinary();
    }

    public String getApiScriptPath() { return apiScriptPath; }
    public void setApiScriptPath(String apiScriptPath) {
        this.apiScriptPath = (apiScriptPath != null) ? OSUtils.cleanPath(apiScriptPath) : "";
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = (username != null && !username.isBlank()) ? username.trim() : "admin"; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = (password != null && !password.isBlank()) ? password.trim() : "sqlmapapi_pass"; }
}
