// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InspectorDataStore;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Scans HTTP responses for user-configured target passwords.
 * Only searches for exact user-provided passwords as requested (no speculative heuristics).
 */
public class PasswordScanner {

    private final List<String> targetPasswords = new CopyOnWriteArrayList<>();
    private volatile boolean caseSensitive = false;

    public PasswordScanner() {}

    public List<String> getPasswords() {
        return new ArrayList<>(targetPasswords);
    }

    public int getPasswordCount() {
        return targetPasswords.size();
    }

    public boolean isCaseSensitive() {
        return caseSensitive;
    }

    public void setCaseSensitive(boolean caseSensitive) {
        this.caseSensitive = caseSensitive;
    }

    public synchronized void setPasswords(Collection<String> passwords) {
        targetPasswords.clear();
        for (String p : passwords) {
            if (p != null && !p.trim().isEmpty()) {
                targetPasswords.add(p.trim());
            }
        }
    }

    public synchronized void addPassword(String password) {
        if (password != null && !password.trim().isEmpty()) {
            String trimmed = password.trim();
            if (!targetPasswords.contains(trimmed)) {
                targetPasswords.add(trimmed);
            }
        }
    }

    public synchronized void clearPasswords() {
        targetPasswords.clear();
    }

    /**
     * Scans the provided HTTP response for any of the configured target passwords.
     */
    public List<FindingEntry> scan(HttpRequestResponse requestResponse, InspectorDataStore dataStore) {
        List<FindingEntry> findings = new ArrayList<>();
        if (targetPasswords.isEmpty() || requestResponse == null || requestResponse.response() == null) {
            return findings;
        }

        HttpResponse response = requestResponse.response();
        String body = ScannerUtils.convertByteArrayToString(response.body());
        String headers = ScannerUtils.extractHeadersString(response);

        for (String targetPassword : targetPasswords) {
            if (targetPassword.length() < 2) {
                continue; // Avoid matching single character noise
            }

            // Check response body
            if (!body.isEmpty()) {
                int idx = caseSensitive ? body.indexOf(targetPassword)
                        : body.toLowerCase().indexOf(targetPassword.toLowerCase());
                if (idx != -1) {
                    findings.add(FindingEntry.create(
                            dataStore.nextId(),
                            FindingCategory.PASSWORD,
                            "Configured Password Leak",
                            targetPassword,
                            "Response Body",
                            requestResponse,
                            idx,
                            idx + targetPassword.length()
                    ));
                }
            }

            // Check response headers with exact offset alignment
            if (!headers.isEmpty()) {
                int hIdx = caseSensitive ? headers.indexOf(targetPassword)
                        : headers.toLowerCase().indexOf(targetPassword.toLowerCase());
                if (hIdx != -1) {
                    findings.add(FindingEntry.create(
                            dataStore.nextId(),
                            FindingCategory.PASSWORD,
                            "Configured Password in Header",
                            targetPassword,
                            "Response Headers",
                            requestResponse,
                            hIdx,
                            hIdx + targetPassword.length()
                    ));
                }
            }
        }

        return findings;
    }

    private static String extractSnippet(String source, String target, boolean caseSens) {
        int index;
        if (caseSens) {
            index = source.indexOf(target);
        } else {
            index = source.toLowerCase().indexOf(target.toLowerCase());
        }
        if (index == -1) return target;

        int start = Math.max(0, index - 30);
        int end = Math.min(source.length(), index + target.length() + 30);
        String snippet = source.substring(start, end).replaceAll("[\\r\\n]+", " ");
        return (start > 0 ? "..." : "") + snippet + (end < source.length() ? "..." : "");
    }
}
