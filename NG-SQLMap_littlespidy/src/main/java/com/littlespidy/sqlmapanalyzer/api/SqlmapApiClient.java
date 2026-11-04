// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.api;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapFinding;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapLogEntry;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapScanStatus;
import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Pure Java REST client for communicating with the SQLMap API server (sqlmapapi.py).
 * Replaces Python/Jython urllib2 with java.net.http.HttpClient.
 * Plain ASCII text only.
 */
public class SqlmapApiClient {

    private final SqlmapApiConfig config;
    private final HttpClient httpClient;
    private final Gson gson;

    public SqlmapApiClient(SqlmapApiConfig config) {
        this.config = config != null ? config : new SqlmapApiConfig();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.gson = new Gson();
    }

    public SqlmapApiConfig getConfig() {
        return config;
    }

    private HttpRequest.Builder newRequestBuilder(String path) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(config.getBaseUrl() + path));

        String user = config.getUsername();
        String pass = config.getPassword();
        if (user != null && !user.isBlank() && pass != null && !pass.isBlank()) {
            String credentials = user + ":" + pass;
            String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            builder.header("Authorization", "Basic " + encoded);
        }
        return builder;
    }

    private String getAsStringSafe(JsonObject obj, String memberName) {
        if (obj == null || !obj.has(memberName)) return "";
        JsonElement el = obj.get(memberName);
        if (el == null || el.isJsonNull()) return "";
        try {
            return el.getAsString();
        } catch (Exception e) {
            return el.toString();
        }
    }

    private String getAsStringSafe(JsonElement el) {
        if (el == null || el.isJsonNull()) return "";
        try {
            return el.getAsString();
        } catch (Exception e) {
            return el.toString();
        }
    }

    private boolean getAsBooleanSafe(JsonElement el) {
        if (el == null || el.isJsonNull()) return false;
        try {
            return el.getAsBoolean();
        } catch (Exception e) {
            return false;
        }
    }

    private int getAsIntSafe(JsonObject obj, String memberName, int defaultVal) {
        if (obj == null || !obj.has(memberName)) return defaultVal;
        JsonElement el = obj.get(memberName);
        if (el == null || el.isJsonNull()) return defaultVal;
        try {
            return el.getAsInt();
        } catch (Exception e) {
            return defaultVal;
        }
    }

    /**
     * Checks if the SQLMap API server is running and responsive.
     */
    public boolean testConnection() {
        return "OK".equals(testConnectionDetails());
    }

    /**
     * Checks connectivity and returns detailed status information.
     */
    public String testConnectionDetails() {
        try {
            HttpRequest request = newRequestBuilder("/task/new")
                    .timeout(Duration.ofSeconds(6))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                if (json != null && json.has("success") && getAsBooleanSafe(json.get("success")) && json.has("taskid")) {
                    String taskId = getAsStringSafe(json, "taskid");
                    if (!taskId.isBlank()) {
                        deleteTask(taskId);
                        return "OK";
                    }
                }
                return "Unexpected server response (HTTP 200, missing task ID)";
            } else if (response.statusCode() == 401) {
                return "401 Unauthorized (Invalid username/password in API Settings)";
            } else {
                return "HTTP Error " + response.statusCode();
            }
        } catch (Exception e) {
            return "Connection failed: " + (e.getMessage() != null ? e.getMessage() : e.toString());
        }
    }

    /**
     * Allocates a new scan task ID from /task/new.
     */
    public String createNewTask() throws IOException, InterruptedException {
        HttpRequest request = newRequestBuilder("/task/new")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            if (json != null && json.has("success") && getAsBooleanSafe(json.get("success")) && json.has("taskid")) {
                return getAsStringSafe(json, "taskid");
            }
        }
        return null;
    }

    /**
     * Deletes a task from /task/<taskId>/delete.
     */
    public boolean deleteTask(String taskId) {
        if (taskId == null || taskId.isBlank()) return false;
        try {
            HttpRequest request = newRequestBuilder("/task/" + taskId + "/delete")
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception ignored) {
            return false;
        }
    }

    /**
     * Retrieves the set of supported option names from /option/<taskId>/list.
     */
    public java.util.Set<String> getSupportedOptions(String taskId) {
        if (taskId == null || taskId.isBlank()) return Collections.emptySet();
        try {
            HttpRequest request = newRequestBuilder("/option/" + taskId + "/list")
                    .timeout(Duration.ofSeconds(6))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                if (json != null && json.has("success") && getAsBooleanSafe(json.get("success")) && json.has("options")) {
                    JsonObject optsObj = json.getAsJsonObject("options");
                    if (optsObj != null) {
                        return optsObj.keySet();
                    }
                }
            }
        } catch (Exception ignored) {}
        return Collections.emptySet();
    }

    /**
     * Sets configuration options on /option/<taskId>/set.
     */
    public boolean setOptions(String taskId, SqlmapTaskOptions options) throws IOException, InterruptedException {
        if (taskId == null || options == null) return false;

        java.util.Map<String, Object> optionMap = new java.util.LinkedHashMap<>(options.toOptionMap());
        java.util.Set<String> supported = getSupportedOptions(taskId);
        if (supported != null && !supported.isEmpty()) {
            optionMap.keySet().removeIf(k -> !supported.contains(k));
        }

        String jsonPayload = gson.toJson(optionMap);
        HttpRequest request = newRequestBuilder("/option/" + taskId + "/set")
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            return json != null && json.has("success") && getAsBooleanSafe(json.get("success"));
        }
        return false;
    }

    /**
     * Initiates scan execution on /scan/<taskId>/start.
     */
    public boolean startScan(String taskId, String targetUrl) throws IOException, InterruptedException {
        if (taskId == null) return false;

        JsonObject payload = new JsonObject();
        payload.addProperty("url", targetUrl != null ? targetUrl : "");

        HttpRequest request = newRequestBuilder("/scan/" + taskId + "/start")
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            return json != null && json.has("success") && getAsBooleanSafe(json.get("success"));
        }
        return false;
    }

    /**
     * Polls the scan status on /scan/<taskId>/status.
     */
    public SqlmapScanStatus getScanStatus(String taskId) throws IOException, InterruptedException {
        if (taskId == null) return new SqlmapScanStatus(false, "invalid task", -1);

        HttpRequest request = newRequestBuilder("/scan/" + taskId + "/status")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            if (json != null && json.has("status") && !json.get("status").isJsonNull()) {
                String status = getAsStringSafe(json, "status");
                int returncode = getAsIntSafe(json, "returncode", -1);
                return new SqlmapScanStatus(true, status, returncode);
            }
        }
        return new SqlmapScanStatus(false, "error", -1);
    }

    /**
     * Retrieves log entries from /scan/<taskId>/log.
     */
    public List<SqlmapLogEntry> getScanLogs(String taskId) throws IOException, InterruptedException {
        if (taskId == null) return Collections.emptyList();

        HttpRequest request = newRequestBuilder("/scan/" + taskId + "/log")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            if (json != null && json.has("success") && getAsBooleanSafe(json.get("success")) && json.has("log") && !json.get("log").isJsonNull() && json.get("log").isJsonArray()) {
                JsonArray arr = json.getAsJsonArray("log");
                List<SqlmapLogEntry> list = new ArrayList<>(arr.size());
                for (JsonElement el : arr) {
                    if (el != null && el.isJsonObject()) {
                        JsonObject obj = el.getAsJsonObject();
                        String level = getAsStringSafe(obj, "level");
                        if (level.isBlank()) level = "INFO";
                        String time = getAsStringSafe(obj, "time");
                        String message = getAsStringSafe(obj, "message");
                        list.add(new SqlmapLogEntry(level, time, message));
                    }
                }
                return list;
            }
        }
        return Collections.emptyList();
    }

    /**
     * Retrieves scan results and vulnerability findings from /scan/<taskId>/data.
     */
    public List<SqlmapFinding> getScanData(String taskId) throws IOException, InterruptedException {
        if (taskId == null) return Collections.emptyList();

        HttpRequest request = newRequestBuilder("/scan/" + taskId + "/data")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            if (json != null && json.has("success") && getAsBooleanSafe(json.get("success")) && json.has("data") && !json.get("data").isJsonNull() && json.get("data").isJsonArray()) {
                JsonArray arr = json.getAsJsonArray("data");
                List<SqlmapFinding> findings = new ArrayList<>();

                for (JsonElement item : arr) {
                    if (item == null || !item.isJsonObject()) continue;
                    try {
                        JsonObject obj = item.getAsJsonObject();
                        int type = getAsIntSafe(obj, "type", -1);
                        JsonElement val = obj.get("value");

                        if (val == null || val.isJsonNull()) {
                            continue;
                        }

                        if (type == 0 && val.isJsonObject()) {
                            // URL & Query parameter
                            JsonObject vObj = val.getAsJsonObject();
                            String url = getAsStringSafe(vObj, "url");
                            String query = getAsStringSafe(vObj, "query");
                            findings.add(new SqlmapFinding(type, query, "", "", "", "Target: " + url));
                        } else if (type == 1 && val.isJsonArray()) {
                            // DBMS & Injection details
                            JsonArray itemsArr = val.getAsJsonArray();
                            for (JsonElement el : itemsArr) {
                                if (el != null && el.isJsonObject()) {
                                    JsonObject findingObj = el.getAsJsonObject();
                                    String dbms = getAsStringSafe(findingObj, "dbms");
                                    String param = getAsStringSafe(findingObj, "parameter");
                                    String place = getAsStringSafe(findingObj, "place");

                                    if (findingObj.has("data") && !findingObj.get("data").isJsonNull() && findingObj.get("data").isJsonObject()) {
                                        JsonObject dataMap = findingObj.getAsJsonObject("data");
                                        for (String k : dataMap.keySet()) {
                                            JsonElement techEl = dataMap.get(k);
                                            if (techEl != null && techEl.isJsonObject()) {
                                                JsonObject techObj = techEl.getAsJsonObject();
                                                String title = getAsStringSafe(techObj, "title");
                                                String payload = getAsStringSafe(techObj, "payload");
                                                findings.add(new SqlmapFinding(type, param + " (" + place + ")", dbms, title, payload, "Confirmed SQL Injection"));
                                            }
                                        }
                                    } else {
                                        findings.add(new SqlmapFinding(type, param, dbms, "", "", "Confirmed Vulnerable Parameter"));
                                    }
                                }
                            }
                        } else if (type == 3) {
                            findings.add(new SqlmapFinding(type, "", "", "Banner", "", getAsStringSafe(val)));
                        } else if (type == 4) {
                            findings.add(new SqlmapFinding(type, "", "", "Current User", "", getAsStringSafe(val)));
                        } else if (type == 5) {
                            findings.add(new SqlmapFinding(type, "", "", "Current Database", "", getAsStringSafe(val)));
                        } else if (type == 6) {
                            findings.add(new SqlmapFinding(type, "", "", "Hostname", "", getAsStringSafe(val)));
                        } else if (type == 7) {
                            findings.add(new SqlmapFinding(type, "", "", "Is DBA", "", getAsBooleanSafe(val) ? "Yes" : "No"));
                        } else {
                            findings.add(new SqlmapFinding(type, "", "", "Enumerated Item (Type " + type + ")", "", getAsStringSafe(val)));
                        }
                    } catch (Exception ignored) {
                        // Protect individual finding parsing against malformed items
                    }
                }
                return findings;
            }
        }
        return Collections.emptyList();
    }

    /**
     * Stops a running scan on /scan/<taskId>/kill.
     */
    public boolean stopScan(String taskId) {
        if (taskId == null) return false;
        try {
            HttpRequest request = newRequestBuilder("/scan/" + taskId + "/kill")
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                return json != null && json.has("success") && getAsBooleanSafe(json.get("success"));
            }
        } catch (Exception ignored) {}
        return false;
    }
}
