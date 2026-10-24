// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.model;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Represents a single WordPress target site and all associated audit results.
 */
public class WordPressTarget_littlespidy {
    private String targetUrl;
    private String rootDomain;
    private String detectedVersion;
    private String scanStatus = "Detected";
    private String detectionDate;

    private final List<VulnerabilityEntry_littlespidy> coreVulnerabilities = new CopyOnWriteArrayList<>();
    private final List<PluginFinding_littlespidy> plugins = new CopyOnWriteArrayList<>();
    private final List<ThemeFinding_littlespidy> themes = new CopyOnWriteArrayList<>();
    private final List<UserFinding_littlespidy> users = new CopyOnWriteArrayList<>();
    private XmlRpcResult_littlespidy xmlRpcResult = new XmlRpcResult_littlespidy();
    private RestApiResult_littlespidy restApiResult = new RestApiResult_littlespidy();
    private final List<String> hardeningFindings = new CopyOnWriteArrayList<>();
    private final List<String> scanLogs = new CopyOnWriteArrayList<>();

    public interface TargetUpdateListener {
        void onTargetUpdated(WordPressTarget_littlespidy target);
        void onLogAdded(WordPressTarget_littlespidy target, String logLine);
    }

    private final transient List<TargetUpdateListener> updateListeners = new CopyOnWriteArrayList<>();

    public WordPressTarget_littlespidy(String targetUrl, String rootDomain) {
        this.targetUrl = targetUrl;
        this.rootDomain = rootDomain;
        this.detectionDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
    }

    public void addListener(TargetUpdateListener listener) {
        if (listener != null && !updateListeners.contains(listener)) {
            updateListeners.add(listener);
        }
    }

    public void removeListener(TargetUpdateListener listener) {
        updateListeners.remove(listener);
    }

    public void notifyUpdate() {
        for (TargetUpdateListener listener : updateListeners) {
            listener.onTargetUpdated(this);
        }
    }

    public synchronized void appendLog(String message) {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        String line = "[" + timestamp + "] " + message;
        scanLogs.add(line);
        for (TargetUpdateListener listener : updateListeners) {
            listener.onLogAdded(this, line);
        }
    }

    public String getTargetUrl() {
        return targetUrl != null ? targetUrl : "";
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public String getRootDomain() {
        return rootDomain != null ? rootDomain : "";
    }

    public void setRootDomain(String rootDomain) {
        this.rootDomain = rootDomain;
    }

    public String getDetectedVersion() {
        return detectedVersion != null && !detectedVersion.isEmpty() ? detectedVersion : "Unknown";
    }

    public void setDetectedVersion(String detectedVersion) {
        this.detectedVersion = detectedVersion;
    }

    public String getScanStatus() {
        return scanStatus;
    }

    public void setScanStatus(String scanStatus) {
        this.scanStatus = scanStatus;
    }

    public String getDetectionDate() {
        return detectionDate;
    }

    public List<VulnerabilityEntry_littlespidy> getCoreVulnerabilities() {
        return coreVulnerabilities;
    }

    public void setCoreVulnerabilities(List<VulnerabilityEntry_littlespidy> vulns) {
        coreVulnerabilities.clear();
        if (vulns != null) {
            coreVulnerabilities.addAll(vulns);
        }
    }

    public List<PluginFinding_littlespidy> getPlugins() {
        return plugins;
    }

    public void addPlugin(PluginFinding_littlespidy plugin) {
        for (PluginFinding_littlespidy p : plugins) {
            if (p.getSlug().equalsIgnoreCase(plugin.getSlug())) {
                return;
            }
        }
        plugins.add(plugin);
    }

    public List<ThemeFinding_littlespidy> getThemes() {
        return themes;
    }

    public void addTheme(ThemeFinding_littlespidy theme) {
        for (ThemeFinding_littlespidy t : themes) {
            if (t.getSlug().equalsIgnoreCase(theme.getSlug())) {
                return;
            }
        }
        themes.add(theme);
    }

    public List<UserFinding_littlespidy> getUsers() {
        return users;
    }

    public void addUser(UserFinding_littlespidy user) {
        for (UserFinding_littlespidy u : users) {
            if (u.getUsername().equalsIgnoreCase(user.getUsername())) {
                return;
            }
        }
        users.add(user);
    }

    public XmlRpcResult_littlespidy getXmlRpcResult() {
        return xmlRpcResult;
    }

    public void setXmlRpcResult(XmlRpcResult_littlespidy xmlRpcResult) {
        this.xmlRpcResult = xmlRpcResult != null ? xmlRpcResult : new XmlRpcResult_littlespidy();
    }

    public RestApiResult_littlespidy getRestApiResult() {
        return restApiResult;
    }

    public void setRestApiResult(RestApiResult_littlespidy restApiResult) {
        this.restApiResult = restApiResult != null ? restApiResult : new RestApiResult_littlespidy();
    }

    public List<String> getHardeningFindings() {
        return hardeningFindings;
    }

    public void addHardeningFinding(String finding) {
        if (!hardeningFindings.contains(finding)) {
            hardeningFindings.add(finding);
        }
    }

    public List<String> getScanLogs() {
        return Collections.unmodifiableList(scanLogs);
    }

    public int getTotalVulnerabilityCount() {
        int count = coreVulnerabilities.size();
        for (PluginFinding_littlespidy p : plugins) {
            count += p.getVulnerabilityCount();
        }
        for (ThemeFinding_littlespidy t : themes) {
            count += t.getVulnerabilityCount();
        }
        return count;
    }
}
