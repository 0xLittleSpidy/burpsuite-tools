// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.activescansessionkeeper.config.SessionKeeperConfig;
import com.littlespidy.activescansessionkeeper.model.ScanActivityDataStore;
import com.littlespidy.activescansessionkeeper.model.ScanActivityEntry;

/**
 * Intercepts HTTP requests and responses from Burp Active Scanner (and optionally other tools),
 * injects updated session credentials, monitors for session expiration, and pauses scan threads.
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
