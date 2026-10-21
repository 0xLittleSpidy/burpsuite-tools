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
import java.time.Duration;
import java.util.ArrayList;
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

    /**
     * Checks if the SQLMap API server is running and responsive.
     */
    public boolean testConnection() {
        try {
            String testTaskId = createNewTask();
            if (testTaskId != null && !testTaskId.isBlank()) {
                deleteTask(testTaskId);
                return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * Allocates a new scan task ID from /task/new.
     */
    public String createNewTask() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getBaseUrl() + "/task/new"))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            if (json != null && json.has("success") && json.get("success").getAsBoolean() && json.has("taskid")) {
                return json.get("taskid").getAsString();
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
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.getBaseUrl() + "/task/" + taskId + "/delete"))
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
     * Sets configuration options on /option/<taskId>/set.
     */
    public boolean setOptions(String taskId, SqlmapTaskOptions options) throws IOException, InterruptedException {
        if (taskId == null || options == null) return false;

        String jsonPayload = gson.toJson(options.toOptionMap());
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getBaseUrl() + "/option/" + taskId + "/set"))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            return json != null && json.has("success") && json.get("success").getAsBoolean();
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

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getBaseUrl() + "/scan/" + taskId + "/start"))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            return json != null && json.has("success") && json.get("success").getAsBoolean();
        }
        return false;
    }

    /**
     * Polls the scan status on /scan/<taskId>/status.
     */
    public SqlmapScanStatus getScanStatus(String taskId) throws IOException, InterruptedException {
        if (taskId == null) return new SqlmapScanStatus(false, "invalid task", -1);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getBaseUrl() + "/scan/" + taskId + "/status"))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            if (json != null && json.has("status")) {
                String status = json.get("status").getAsString();
                int returncode = json.has("returncode") && !json.get("returncode").isJsonNull()
                        ? json.get("returncode").getAsInt() : -1;
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

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getBaseUrl() + "/scan/" + taskId + "/log"))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            if (json != null && json.has("success") && json.get("success").getAsBoolean() && json.has("log")) {
                JsonArray arr = json.getAsJsonArray("log");
                List<SqlmapLogEntry> list = new ArrayList<>(arr.size());
                for (JsonElement el : arr) {
                    if (el.isJsonObject()) {
                        JsonObject obj = el.getAsJsonObject();
                        String level = obj.has("level") ? obj.get("level").getAsString() : "INFO";
                        String time = obj.has("time") ? obj.get("time").getAsString() : "";
                        String message = obj.has("message") ? obj.get("message").getAsString() : "";
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

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getBaseUrl() + "/scan/" + taskId + "/data"))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            JsonObject json = gson.fromJson(response.body(), JsonObject.class);
            if (json != null && json.has("success") && json.get("success").getAsBoolean() && json.has("data")) {
                JsonArray arr = json.getAsJsonArray("data");
                List<SqlmapFinding> findings = new ArrayList<>();

                for (JsonElement item : arr) {
                    if (!item.isJsonObject()) continue;
                    JsonObject obj = item.getAsJsonObject();
                    int type = obj.has("type") ? obj.get("type").getAsInt() : -1;
                    JsonElement val = obj.get("value");

                    if (type == 0 && val != null && val.isJsonObject()) {
                        // URL & Query parameter
                        JsonObject vObj = val.getAsJsonObject();
                        String url = vObj.has("url") ? vObj.get("url").getAsString() : "";
                        String query = vObj.has("query") ? vObj.get("query").getAsString() : "";
                        findings.add(new SqlmapFinding(type, query, "", "", "", "Target: " + url));
                    } else if (type == 1 && val != null && val.isJsonArray()) {
                        // DBMS & Injection details
                        JsonArray itemsArr = val.getAsJsonArray();
                        for (JsonElement el : itemsArr) {
                            if (el.isJsonObject()) {
                                JsonObject findingObj = el.getAsJsonObject();
                                String dbms = findingObj.has("dbms") ? findingObj.get("dbms").getAsString() : "";
                                String param = findingObj.has("parameter") ? findingObj.get("parameter").getAsString() : "";
                                String place = findingObj.has("place") ? findingObj.get("place").getAsString() : "";

                                if (findingObj.has("data") && findingObj.get("data").isJsonObject()) {
                                    JsonObject dataMap = findingObj.getAsJsonObject("data");
                                    for (String k : dataMap.keySet()) {
                                        JsonObject techObj = dataMap.getAsJsonObject(k);
                                        String title = techObj.has("title") ? techObj.get("title").getAsString() : "";
                                        String payload = techObj.has("payload") ? techObj.get("payload").getAsString() : "";
                                        findings.add(new SqlmapFinding(type, param + " (" + place + ")", dbms, title, payload, "Confirmed SQL Injection"));
                                    }
                                } else {
                                    findings.add(new SqlmapFinding(type, param, dbms, "", "", "Confirmed Vulnerable Parameter"));
                                }
                            }
                        }
                    } else if (type == 3 && val != null) {
                        findings.add(new SqlmapFinding(type, "", "", "Banner", "", val.getAsString()));
                    } else if (type == 4 && val != null) {
                        findings.add(new SqlmapFinding(type, "", "", "Current User", "", val.getAsString()));
                    } else if (type == 5 && val != null) {
                        findings.add(new SqlmapFinding(type, "", "", "Current Database", "", val.getAsString()));
                    } else if (type == 6 && val != null) {
                        findings.add(new SqlmapFinding(type, "", "", "Hostname", "", val.getAsString()));
                    } else if (type == 7 && val != null) {
                        findings.add(new SqlmapFinding(type, "", "", "Is DBA", "", val.getAsBoolean() ? "Yes" : "No"));
                    } else if (val != null) {
                        findings.add(new SqlmapFinding(type, "", "", "Enumerated Item (Type " + type + ")", "", val.toString()));
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
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(config.getBaseUrl() + "/scan/" + taskId + "/kill"))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                return json != null && json.has("success") && json.get("success").getAsBoolean();
            }
        } catch (Exception ignored) {}
        return false;
    }
}
