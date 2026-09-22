// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;
import com.littlespidy.activescansessionkeeper.model.ScanActivityDataStore;
import com.littlespidy.activescansessionkeeper.model.ScanActivityEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Intercepts HTTP requests and responses from Burp Active Scanner (and optionally other tools),
 * injects updated session credentials, monitors for session expiration, and pauses scan threads.
 * Also sniffs Burp Proxy traffic while the cookie prompt is open to capture fresh session cookies.
 *
 * @author littlespidy
 */
public class ActiveScanHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final SessionKeeperConfig config;
    private final ScanSessionCoordinator coordinator;
    private final ExpirationDetector detector;
    private final ScanActivityDataStore dataStore;

    public ActiveScanHttpHandler(MontoyaApi api, SessionKeeperConfig config,
                                 ScanSessionCoordinator coordinator,
                                 ExpirationDetector detector,
                                 ScanActivityDataStore dataStore) {
        this.api = api;
        this.config = config;
        this.coordinator = coordinator;
        this.detector = detector;
        this.dataStore = dataStore;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // ── Sniff Proxy requests when cookie prompt is actively open ──
        if (requestToBeSent.toolSource().toolType() == ToolType.PROXY && coordinator.isPromptOpen()) {
            if (config.matchesHost(requestToBeSent.httpService().host()) && requestToBeSent.hasHeader("Cookie")) {
                String cookieVal = requestToBeSent.headerValue("Cookie");
                if (cookieVal != null && !cookieVal.trim().isEmpty()) {
                    CapturedCookieEvent event = new CapturedCookieEvent(cookieVal.trim(), requestToBeSent.url(), requestToBeSent.method());
                    coordinator.notifyCookieCaptured(event);
                }
            }
        }

        if (!config.isEnabled() || !isMonitoredTool(requestToBeSent.toolSource().toolType())) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Scope check
        if (config.isInScopeOnly() && !api.scope().isInScope(requestToBeSent.url())) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Host filter
        String host = requestToBeSent.httpService().host();
        if (!config.matchesHost(host)) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // If scanner is currently paused (waiting for user cookie prompt), wait until resumed!
        coordinator.waitForResumeIfPaused();

        // Mutate request with current valid session credentials
        HttpRequest modified = coordinator.applySessionCredentials(requestToBeSent);

        return RequestToBeSentAction.continueWith(modified);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // ── Sniff Proxy responses when cookie prompt is actively open ──
        if (responseReceived.toolSource().toolType() == ToolType.PROXY && coordinator.isPromptOpen()) {
            HttpRequest initReq = responseReceived.initiatingRequest();
            if (initReq != null && config.matchesHost(initReq.httpService().host())) {
                List<String> setCookies = new ArrayList<>();
                for (HttpHeader h : responseReceived.headers()) {
                    if (h.name().equalsIgnoreCase("Set-Cookie")) {
                        String val = h.value();
                        if (!val.toLowerCase(Locale.ROOT).contains("max-age=0") &&
                            !val.toLowerCase(Locale.ROOT).contains("1970") &&
                            !val.toLowerCase(Locale.ROOT).contains("deleted")) {
                            int semi = val.indexOf(';');
                            String pair = (semi > 0) ? val.substring(0, semi).trim() : val.trim();
                            if (!pair.isEmpty()) {
                                setCookies.add(pair);
                            }
                        }
                    }
                }
                if (!setCookies.isEmpty()) {
                    String combined = String.join("; ", setCookies);
                    CapturedCookieEvent event = new CapturedCookieEvent(combined, initReq.url(), initReq.method());
                    coordinator.notifyCookieCaptured(event);
                }
            }
        }

        if (!config.isEnabled() || !isMonitoredTool(responseReceived.toolSource().toolType())) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        HttpRequest initiatingRequest = responseReceived.initiatingRequest();
        if (initiatingRequest == null) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Scope check
        if (config.isInScopeOnly() && !api.scope().isInScope(initiatingRequest.url())) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Host filter
        String host = initiatingRequest.httpService().host();
        if (!config.matchesHost(host)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Check if response indicates session expiration
        ExpirationResult result = detector.evaluate(responseReceived);

        if (result.isExpired()) {
            // Session expired! Pause scanner and prompt user for fresh cookies
            HttpResponse retryResponse = coordinator.handleExpiration(
                    result.getReason(),
                    result.getDetails(),
                    initiatingRequest,
                    responseReceived
            );

            // If auto-retry succeeded, return the fresh response to the scanner instead of the expired 401/302!
            if (retryResponse != null) {
                return ResponseReceivedAction.continueWith(retryResponse);
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private boolean isMonitoredTool(ToolType toolType) {
        if (toolType == null) return false;
        if (toolType == ToolType.SCANNER && config.isMonitorScanner()) return true;
        if (toolType == ToolType.REPEATER && config.isMonitorRepeater()) return true;
        if (toolType == ToolType.INTRUDER && config.isMonitorIntruder()) return true;
        if (toolType == ToolType.EXTENSIONS && config.isMonitorExtensions()) return true;
        return false;
    }
}
