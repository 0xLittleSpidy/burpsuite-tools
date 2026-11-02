// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InspectorDataStore;
import com.littlespidy.responseinspector.model.SecretClassificationManager;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Coordinates response scanning across all 5 analyzers.
 */
public class ResponseScanEngine {

    private final Map<FindingCategory, InspectorDataStore> dataStores = new EnumMap<>(FindingCategory.class);
    private final PasswordScanner passwordScanner = new PasswordScanner();
    private final PiiNetworkPathScanner piiScanner = new PiiNetworkPathScanner();
    private final ErrorScanner errorScanner = new ErrorScanner();
    private final SecretScanner secretScanner = new SecretScanner();
    private final CommentScanner commentScanner = new CommentScanner();
    private final SecretClassificationManager secretClassificationManager = new SecretClassificationManager();

    public ResponseScanEngine() {
        for (FindingCategory category : FindingCategory.values()) {
            dataStores.put(category, new InspectorDataStore(category));
        }
    }

    public InspectorDataStore getDataStore(FindingCategory category) {
        return dataStores.get(category);
    }

    public PasswordScanner getPasswordScanner() {
        return passwordScanner;
    }

    public PiiNetworkPathScanner getPiiScanner() {
        return piiScanner;
    }

    public ErrorScanner getErrorScanner() {
        return errorScanner;
    }

    public SecretScanner getSecretScanner() {
        return secretScanner;
    }

    public CommentScanner getCommentScanner() {
        return commentScanner;
    }

    public SecretClassificationManager getSecretClassificationManager() {
        return secretClassificationManager;
    }

    private com.littlespidy.responseinspector.storage.PersistentStorageManager storageManager;

    public com.littlespidy.responseinspector.storage.PersistentStorageManager getStorageManager() {
        return storageManager;
    }

    public void setStorageManager(com.littlespidy.responseinspector.storage.PersistentStorageManager storageManager) {
        this.storageManager = storageManager;
    }

    private final List<HttpRequestResponse> repeaterTraffic = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final List<HttpRequestResponse> loadedTraffic = new java.util.concurrent.CopyOnWriteArrayList<>();

    public void addLoadedTraffic(Collection<HttpRequestResponse> items) {
        if (items != null) {
            for (HttpRequestResponse item : items) {
                if (item != null && item.hasResponse() && !loadedTraffic.contains(item)) {
                    loadedTraffic.add(item);
                }
            }
        }
    }

    public List<HttpRequestResponse> getLoadedTraffic() {
        return new ArrayList<>(loadedTraffic);
    }

    public int getLoadedTrafficCount() {
        return loadedTraffic.size();
    }

    public void clearLoadedTraffic() {
        loadedTraffic.clear();
    }

    public void addRepeaterItem(HttpRequestResponse item) {
        if (item != null && item.hasResponse()) {
            repeaterTraffic.add(item);
        }
    }

    public List<HttpRequestResponse> getRepeaterTraffic() {
        return new ArrayList<>(repeaterTraffic);
    }

    public int getRepeaterTrafficCount() {
        return repeaterTraffic.size();
    }

    public void clearRepeaterTraffic() {
        repeaterTraffic.clear();
    }

    public int scanProxyItem(ProxyHttpRequestResponse item) {
        if (item == null || !item.hasResponse()) {
            return 0;
        }
        var req = item.finalRequest() != null ? item.finalRequest() : item.request();
        HttpRequestResponse hrr = HttpRequestResponse.httpRequestResponse(req, item.response(), item.annotations());
        return scanItem(hrr);
    }

    /**
     * Scans a single HTTP request/response for a specific category only.
     *
     * @param category category to scan for
     * @param item HTTP request/response item
     * @return count of new findings added
     */
    public int scanCategoryItem(FindingCategory category, HttpRequestResponse item) {
        if (item == null || item.response() == null || category == null) {
            return 0;
        }

        if (ScannerUtils.isResponseEmpty(item.response()) ||
            ScannerUtils.isStaticResource(item.request(), item.response()) ||
            ScannerUtils.isOversized(item.response())) {
            return 0;
        }

        int newFindings = 0;
        InspectorDataStore store = dataStores.get(category);
        if (store == null) {
            return 0;
        }

        List<FindingEntry> entries = switch (category) {
            case PASSWORD -> passwordScanner.scan(item, store);
            case PII_NETWORK_PATH -> piiScanner.scan(item, store);
            case ERROR -> errorScanner.scan(item, store);
            case SECRET -> secretScanner.scan(item, store);
            case COMMENT -> commentScanner.scan(item, store);
        };

        for (FindingEntry entry : entries) {
            if (store.addEntry(entry)) {
                newFindings++;
            }
        }

        if (newFindings > 0 && storageManager != null) {
            storageManager.scheduleAutoSave();
        }

        return newFindings;
    }

    /**
     * Scans a single HTTP request/response across all 5 categories and populates the data stores.
     *
     * @return count of new findings added
     */
    public int scanItem(HttpRequestResponse item) {
        if (item == null || item.response() == null) {
            return 0;
        }

        // Early-exit pre-filters: empty responses, static resources (JS, CSS, images, fonts, binaries), oversized
        if (ScannerUtils.isResponseEmpty(item.response()) ||
            ScannerUtils.isStaticResource(item.request(), item.response()) ||
            ScannerUtils.isOversized(item.response())) {
            return 0;
        }

        int newFindings = 0;

        // 1. Passwords
        List<FindingEntry> passFindings = passwordScanner.scan(item, dataStores.get(FindingCategory.PASSWORD));
        for (FindingEntry entry : passFindings) {
            if (dataStores.get(FindingCategory.PASSWORD).addEntry(entry)) {
                newFindings++;
            }
        }

        // 2. PII, Network & OS Paths
        List<FindingEntry> piiFindings = piiScanner.scan(item, dataStores.get(FindingCategory.PII_NETWORK_PATH));
        for (FindingEntry entry : piiFindings) {
            if (dataStores.get(FindingCategory.PII_NETWORK_PATH).addEntry(entry)) {
                newFindings++;
            }
        }

        // 3. Errors & Exceptions
        List<FindingEntry> errorFindings = errorScanner.scan(item, dataStores.get(FindingCategory.ERROR));
        for (FindingEntry entry : errorFindings) {
            if (dataStores.get(FindingCategory.ERROR).addEntry(entry)) {
                newFindings++;
            }
        }

        // 4. Secrets & Tokens
        List<FindingEntry> secretFindings = secretScanner.scan(item, dataStores.get(FindingCategory.SECRET));
        for (FindingEntry entry : secretFindings) {
            if (dataStores.get(FindingCategory.SECRET).addEntry(entry)) {
                newFindings++;
            }
        }

        // 5. Developer Comments
        List<FindingEntry> commentFindings = commentScanner.scan(item, dataStores.get(FindingCategory.COMMENT));
        for (FindingEntry entry : commentFindings) {
            if (dataStores.get(FindingCategory.COMMENT).addEntry(entry)) {
                newFindings++;
            }
        }

        if (newFindings > 0 && storageManager != null) {
            storageManager.scheduleAutoSave();
        }

        return newFindings;
    }

    public void clearAll() {
        for (InspectorDataStore store : dataStores.values()) {
            store.clear();
        }
    }
}
