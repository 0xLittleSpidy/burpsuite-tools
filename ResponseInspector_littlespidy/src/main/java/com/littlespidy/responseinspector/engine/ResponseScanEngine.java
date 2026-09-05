// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InspectorDataStore;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Coordinates response scanning across all 4 analyzers.
 */
public class ResponseScanEngine {

    private final Map<FindingCategory, InspectorDataStore> dataStores = new EnumMap<>(FindingCategory.class);
    private final PasswordScanner passwordScanner = new PasswordScanner();
    private final PiiNetworkPathScanner piiScanner = new PiiNetworkPathScanner();
    private final ErrorScanner errorScanner = new ErrorScanner();
    private final SecretScanner secretScanner = new SecretScanner();

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

    public int scanProxyItem(ProxyHttpRequestResponse item) {
        if (item == null || !item.hasResponse()) {
            return 0;
        }
        var req = item.finalRequest() != null ? item.finalRequest() : item.request();
        HttpRequestResponse hrr = HttpRequestResponse.httpRequestResponse(req, item.response(), item.annotations());
        return scanItem(hrr);
    }

    /**
     * Scans a single HTTP request/response across all categories and populates the data stores.
     *
     * @return count of new findings added
     */
    public int scanItem(HttpRequestResponse item) {
        if (item == null || item.response() == null) {
            return 0;
        }

        // Early-exit pre-filters from sensitive-discoverer
        if (ScannerUtils.isResponseEmpty(item.response()) ||
            ScannerUtils.isMimeTypeBlacklisted(item.response()) ||
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

        return newFindings;
    }

    public void clearAll() {
        for (InspectorDataStore store : dataStores.values()) {
            store.clear();
        }
    }
}
