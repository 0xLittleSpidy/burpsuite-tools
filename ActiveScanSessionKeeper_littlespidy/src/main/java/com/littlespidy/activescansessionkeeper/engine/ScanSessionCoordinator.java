// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.activescansessionkeeper.config.CookieMode;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;
import com.littlespidy.activescansessionkeeper.model.ScanActivityDataStore;
import com.littlespidy.activescansessionkeeper.model.ScanActivityEntry;
import com.littlespidy.activescansessionkeeper.ui.CookiePromptDialog;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Coordinates thread synchronization, scan pausing/resuming, cookie injection,
 * and user prompting when session expiration is detected during active scanning.
 *
 * @author littlespidy
 */
public class ScanSessionCoordinator {

    private final MontoyaApi api;
    private final SessionKeeperConfig config;
    private final ScanActivityDataStore dataStore;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition unpausedCondition = lock.newCondition();

    private final AtomicBoolean isPaused = new AtomicBoolean(false);
    private final AtomicBoolean isPromptOpen = new AtomicBoolean(false);

    public ScanSessionCoordinator(MontoyaApi api, SessionKeeperConfig config, ScanActivityDataStore dataStore) {
        this.api = api;
        this.config = config;
        this.dataStore = dataStore;
    }

    /**
     * Checks if scanner threads are currently paused.
     */
    public boolean isPaused() {
        return isPaused.get();
    }

    /**
     * Blocks the calling thread while the scanner is in a paused state.
     */
    public void waitForResumeIfPaused() {
        while (isPaused.get()) {
            lock.lock();
            try {
                if (isPaused.get()) {
                    unpausedCondition.await(500, TimeUnit.MILLISECONDS);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * Manually pause scanner execution.
     */
    public void pauseScanManually() {
        isPaused.set(true);
        dataStore.addEntry(new ScanActivityEntry(
                dataStore.nextId(), "Manual", "-", "-", "-", 0,
                "SCAN_PAUSED", "Scanner paused manually by user.", null
        ));
    }

    /**
     * Manually resume scanner execution.
     */
    public void resumeScan() {
        isPaused.set(false);
        lock.lock();
        try {
            unpausedCondition.signalAll();
        } finally {
            lock.unlock();
        }
        dataStore.addEntry(new ScanActivityEntry(
                dataStore.nextId(), "Manual", "-", "-", "-", 0,
                "SCAN_RESUMED", "Scanner resumed.", null
        ));
    }

    /**
     * Called when an expired response is intercepted. Pauses scanning, displays prompt,
     * updates credentials, and resumes scanner threads.
     *
     * @return the retried response if auto-retry is enabled and succeeded, or null
     */
    public HttpResponse handleExpiration(String reason, String details, HttpRequest initiatingRequest, HttpResponse expiredResponse) {
        String url = (initiatingRequest != null) ? initiatingRequest.url() : "Unknown URL";
        String host = (initiatingRequest != null) ? initiatingRequest.httpService().host() : "Unknown Host";
        String method = (initiatingRequest != null) ? initiatingRequest.method() : "GET";
        int status = (expiredResponse != null) ? expiredResponse.statusCode() : 0;

        HttpRequestResponse reqResp = null;
        if (initiatingRequest != null && expiredResponse != null) {
            reqResp = HttpRequestResponse.httpRequestResponse(initiatingRequest, expiredResponse);
        }

        // Check if another thread is already prompting the user
        if (isPromptOpen.compareAndSet(false, true)) {
            // First thread to detect expiry: pause scanner and prompt user
            isPaused.set(true);

            dataStore.addEntry(new ScanActivityEntry(
                    dataStore.nextId(), "Scanner", method, host, url, status,
                    "SESSION_EXPIRED", "Detected: " + reason + " - Scanner paused, waiting for user input.", reqResp
            ));

            if (config.isSoundAlertOnExpire()) {
                try {
                    Toolkit.getDefaultToolkit().beep();
                } catch (Exception ignored) {}
            }

            try {
                // Show modal Swing prompt on EDT
                if (SwingUtilities.isEventDispatchThread()) {
                    showPromptModal(reason, details, url, initiatingRequest);
                } else {
                    SwingUtilities.invokeAndWait(() -> showPromptModal(reason, details, url, initiatingRequest));
                }
            } catch (Exception e) {
                api.logging().logToError("Error displaying cookie prompt dialog: " + e.getMessage());
            } finally {
                // Resume scan threads
                isPromptOpen.set(false);
                isPaused.set(false);
                lock.lock();
                try {
                    unpausedCondition.signalAll();
                } finally {
                    lock.unlock();
                }
            }
        } else {
            // Another thread is already prompting; wait for that thread to finish
            waitForResumeIfPaused();
        }

        // Retry the request if auto-retry is enabled
        if (config.isAutoRetryOnExpire() && initiatingRequest != null) {
            try {
                HttpRequest retriedRequest = applySessionCredentials(initiatingRequest);
                HttpRequestResponse retriedReqResp = api.http().sendRequest(retriedRequest);
                HttpResponse retriedResponse = retriedReqResp.response();

                dataStore.addEntry(new ScanActivityEntry(
                        dataStore.nextId(), "Scanner", method, host, url, retriedResponse.statusCode(),
                        "REQUEST_RETRIED", "Re-sent failed request with fresh cookie. New status: " + retriedResponse.statusCode(), retriedReqResp
                ));

                return retriedResponse;
            } catch (Exception e) {
                api.logging().logToError("Failed to retry request after session refresh: " + e.getMessage());
            }
        }

        return null;
    }

    private void showPromptModal(String reason, String details, String url, HttpRequest initiatingRequest) {
        Window parent = api.userInterface().swingUtils().suiteFrame();
        CookiePromptDialog dialog = new CookiePromptDialog(parent, config, reason, details, url, initiatingRequest, (newCookie, retrySelected) -> {
            dataStore.addEntry(new ScanActivityEntry(
                    dataStore.nextId(), "User", "-", "-", url, 0,
                    "COOKIE_UPDATED", "New session cookie applied: " + truncate(newCookie, 40), null
            ));
        });
        dialog.setVisible(true);
    }

    /**
     * Injects configured session cookie(s) and auth header into the outgoing request.
     */
    public HttpRequest applySessionCredentials(HttpRequest request) {
        if (!config.isEnabled() || request == null) {
            return request;
        }

        HttpRequest mutated = request;
        boolean modified = false;

        CookieMode mode = config.getCookieMode();

        if (mode == CookieMode.FULL_COOKIE_HEADER) {
            String fullCookie = config.getFullCookieHeader();
            if (fullCookie != null && !fullCookie.trim().isEmpty()) {
                if (mutated.hasHeader("Cookie")) {
                    mutated = mutated.withUpdatedHeader("Cookie", fullCookie.trim());
                } else {
                    mutated = mutated.withAddedHeader("Cookie", fullCookie.trim());
                }
                modified = true;
            }
        } else if (mode == CookieMode.NAMED_COOKIES) {
            String cookieVal = config.getCookieValue();
            if (cookieVal != null && !cookieVal.trim().isEmpty()) {
                List<String> targetNames = config.parseCookieNames();
                String existingCookie = mutated.hasHeader("Cookie") ? mutated.headerValue("Cookie") : "";
                String updatedCookie = updateNamedCookies(existingCookie, targetNames, cookieVal);

                if (mutated.hasHeader("Cookie")) {
                    mutated = mutated.withUpdatedHeader("Cookie", updatedCookie);
                } else {
                    mutated = mutated.withAddedHeader("Cookie", updatedCookie);
                }
                modified = true;
            }
        }

        // Authorization Bearer token header injection
        if (config.isUpdateAuthBearer() || mode == CookieMode.AUTHORIZATION_BEARER) {
            String token = config.getAuthBearerToken();
            if (token != null && !token.trim().isEmpty()) {
                String cleanToken = token.trim();
                if (cleanToken.toLowerCase(Locale.ROOT).startsWith("bearer ")) {
                    cleanToken = cleanToken.substring(7).trim();
                }
                if (mutated.hasHeader("Authorization")) {
                    mutated = mutated.withUpdatedHeader("Authorization", "Bearer " + cleanToken);
                } else {
                    mutated = mutated.withAddedHeader("Authorization", "Bearer " + cleanToken);
                }
                modified = true;
            }
        }

        return mutated;
    }

    private String updateNamedCookies(String existingCookieHeader, List<String> targetNames, String newValue) {
        if (existingCookieHeader == null || existingCookieHeader.trim().isEmpty()) {
            // No existing cookies: construct new cookies from target names
            if (newValue.contains("=")) {
                return newValue;
            }
            if (!targetNames.isEmpty()) {
                return targetNames.get(0) + "=" + newValue;
            }
            return newValue;
        }

        // Check if newValue is a full key=value string (e.g. JSESSIONID=abc123)
        Map<String, String> newPairs = new HashMap<>();
        if (newValue.contains("=")) {
            String[] tokens = newValue.split(";\\s*");
            for (String t : tokens) {
                int eq = t.indexOf('=');
                if (eq > 0) {
                    newPairs.put(t.substring(0, eq).trim().toLowerCase(Locale.ROOT), t.substring(eq + 1).trim());
                }
            }
        }

        String[] pairs = existingCookieHeader.split(";\\s*");
        List<String> result = new ArrayList<>();
        Set<String> matchedTargets = new HashSet<>();

        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String name = pair.substring(0, eq).trim();
                String nameLower = name.toLowerCase(Locale.ROOT);

                if (newPairs.containsKey(nameLower)) {
                    result.add(name + "=" + newPairs.get(nameLower));
                    matchedTargets.add(nameLower);
                } else {
                    boolean isTarget = false;
                    for (String tn : targetNames) {
                        if (tn.equalsIgnoreCase(name)) {
                            isTarget = true;
                            break;
                        }
                    }
                    if (isTarget) {
                        result.add(name + "=" + newValue);
                        matchedTargets.add(nameLower);
                    } else {
                        result.add(pair);
                    }
                }
            } else {
                result.add(pair);
            }
        }

        // If target cookie wasn't in the original request, append it
        if (!newPairs.isEmpty()) {
            for (Map.Entry<String, String> entry : newPairs.entrySet()) {
                if (!matchedTargets.contains(entry.getKey())) {
                    result.add(entry.getKey() + "=" + entry.getValue());
                }
            }
        } else if (!targetNames.isEmpty() && matchedTargets.isEmpty()) {
            result.add(targetNames.get(0) + "=" + newValue);
        }

        return String.join("; ", result);
    }

    private String truncate(String text, int max) {
        if (text == null) return "";
        return (text.length() <= max) ? text : text.substring(0, max) + "...";
    }
}
