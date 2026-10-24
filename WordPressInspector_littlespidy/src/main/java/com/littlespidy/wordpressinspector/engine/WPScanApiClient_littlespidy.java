// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.engine;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.littlespidy.wordpressinspector.model.VulnerabilityEntry_littlespidy;
import com.littlespidy.wordpressinspector.model.WordPressDataStore_littlespidy;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Client for interacting with the official WPScan API v3 database.
 */
public class WPScanApiClient_littlespidy {

    private static final String BASE_API_URL = "https://wpscan.com/api/v3/";
    private final WordPressDataStore_littlespidy dataStore;

    public WPScanApiClient_littlespidy(WordPressDataStore_littlespidy dataStore) {
        this.dataStore = dataStore;
    }

    public List<VulnerabilityEntry_littlespidy> scanCoreVersion(String version, String apiKey) throws Exception {
        if (version == null || version.trim().isEmpty()) {
            return new ArrayList<>();
        }
        String cleanVersion = version.trim();
        String versionNoDots = cleanVersion.replace(".", "");

        // 1. Check 24-hour cache
        if (dataStore != null) {
            WordPressDataStore_littlespidy.CachedApiEntry_littlespidy cached = dataStore.getCachedEntry("core", cleanVersion);
            if (cached != null) {
                return cached.getVulnerabilities();
            }
        }

        String endpoint = "wordpresses/" + versionNoDots;
        List<VulnerabilityEntry_littlespidy> vulns = executeQuery(endpoint, apiKey, List.of(versionNoDots, cleanVersion));

        if (dataStore != null) {
            dataStore.putCacheEntry("core", cleanVersion, vulns);
        }
        return vulns;
    }

    public List<VulnerabilityEntry_littlespidy> scanPlugin(String slug, String apiKey) throws Exception {
        if (slug == null || slug.trim().isEmpty()) {
            return new ArrayList<>();
        }
        String cleanSlug = WordPressDetectionEngine_littlespidy.normalizeSlug(slug);

        // 1. Check 24-hour cache
        if (dataStore != null) {
            WordPressDataStore_littlespidy.CachedApiEntry_littlespidy cached = dataStore.getCachedEntry("plugin", cleanSlug);
            if (cached != null) {
                return cached.getVulnerabilities();
            }
        }

        String endpoint = "plugins/" + cleanSlug;
        List<VulnerabilityEntry_littlespidy> vulns = executeQuery(endpoint, apiKey, List.of(cleanSlug));

        if (dataStore != null) {
            dataStore.putCacheEntry("plugin", cleanSlug, vulns);
        }
        return vulns;
    }

    public List<VulnerabilityEntry_littlespidy> scanTheme(String slug, String apiKey) throws Exception {
        if (slug == null || slug.trim().isEmpty()) {
            return new ArrayList<>();
        }
        String cleanSlug = WordPressDetectionEngine_littlespidy.normalizeSlug(slug);

        // 1. Check 24-hour cache
        if (dataStore != null) {
            WordPressDataStore_littlespidy.CachedApiEntry_littlespidy cached = dataStore.getCachedEntry("theme", cleanSlug);
            if (cached != null) {
                return cached.getVulnerabilities();
            }
        }

        String endpoint = "themes/" + cleanSlug;
        List<VulnerabilityEntry_littlespidy> vulns = executeQuery(endpoint, apiKey, List.of(cleanSlug));

        if (dataStore != null) {
            dataStore.putCacheEntry("theme", cleanSlug, vulns);
        }
        return vulns;
    }

    public boolean testApiKey(String apiKey) {
        if (apiKey == null || apiKey.trim().isEmpty()) {
            return false;
        }
        try {
            URL url = URI.create(BASE_API_URL + "wordpresses/64").toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Token token=" + apiKey.trim());
            conn.setRequestProperty("User-Agent", "WordPressInspector-littlespidy/1.0.0");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);

            int code = conn.getResponseCode();
            return code == 200 || code == 429;
        } catch (Exception e) {
            return false;
        }
    }

    private List<VulnerabilityEntry_littlespidy> executeQuery(String endpoint, String apiKey, List<String> candidateKeys) throws Exception {
        List<VulnerabilityEntry_littlespidy> results = new ArrayList<>();
        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new IllegalArgumentException("WPScan API key is not configured.");
        }

        URL url = URI.create(BASE_API_URL + endpoint).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Token token=" + apiKey.trim());
        conn.setRequestProperty("User-Agent", "WordPressInspector-littlespidy/1.0.0");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(12000);

        int code = conn.getResponseCode();
        if (dataStore != null) {
            dataStore.getConfig().incrementDailyApiCounter();
        }

        if (code == 404) {
            // Slug or version is clean or not tracked in WPScan DB
            return results;
        }
        if (code == 401) {
            throw new IllegalStateException("HTTP 401: Invalid WPScan API key.");
        }
        if (code == 429) {
            throw new IllegalStateException("HTTP 429: WPScan API rate limit exceeded.");
        }
        if (code != 200) {
            throw new IllegalStateException("HTTP " + code + " from WPScan API.");
        }

        try (InputStream is = conn.getInputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }

            JsonObject root = JsonParser.parseString(sb.toString()).getAsJsonObject();
            for (String key : candidateKeys) {
                if (root.has(key) && root.get(key).isJsonObject()) {
                    JsonObject itemObj = root.getAsJsonObject(key);
                    if (itemObj.has("vulnerabilities") && itemObj.get("vulnerabilities").isJsonArray()) {
                        JsonArray vulnsArr = itemObj.getAsJsonArray("vulnerabilities");
                        for (JsonElement elem : vulnsArr) {
                            if (elem.isJsonObject()) {
                                results.add(parseVulnerability(elem.getAsJsonObject()));
                            }
                        }
                    }
                    break;
                }
            }
        }
        return results;
    }

    private VulnerabilityEntry_littlespidy parseVulnerability(JsonObject obj) {
        VulnerabilityEntry_littlespidy entry = new VulnerabilityEntry_littlespidy();
        if (obj.has("title") && !obj.get("title").isJsonNull()) {
            entry.setTitle(obj.get("title").getAsString());
        }
        if (obj.has("vuln_type") && !obj.get("vuln_type").isJsonNull()) {
            entry.setVulnType(obj.get("vuln_type").getAsString());
        }
        if (obj.has("fixed_in") && !obj.get("fixed_in").isJsonNull()) {
            entry.setFixedIn(obj.get("fixed_in").getAsString());
        }
        if (obj.has("published_date") && !obj.get("published_date").isJsonNull()) {
            entry.setPublishedDate(obj.get("published_date").getAsString());
        }
        if (obj.has("cvss") && obj.get("cvss").isJsonObject()) {
            JsonObject cvssObj = obj.getAsJsonObject("cvss");
            if (cvssObj.has("score") && !cvssObj.get("score").isJsonNull()) {
                entry.setCvssScore(cvssObj.get("score").getAsString());
            }
        }

        if (obj.has("references") && obj.get("references").isJsonObject()) {
            JsonObject refObj = obj.getAsJsonObject("references");
            if (refObj.has("cve") && refObj.get("cve").isJsonArray()) {
                List<String> cves = new ArrayList<>();
                for (JsonElement cveElem : refObj.getAsJsonArray("cve")) {
                    cves.add("CVE-" + cveElem.getAsString());
                }
                entry.setCveList(cves);
            }
            if (refObj.has("url") && refObj.get("url").isJsonArray()) {
                List<String> urls = new ArrayList<>();
                for (JsonElement urlElem : refObj.getAsJsonArray("url")) {
                    urls.add(urlElem.getAsString());
                }
                entry.setReferences(urls);
            }
        }
        return entry;
    }
}
