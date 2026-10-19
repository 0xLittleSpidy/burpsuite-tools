// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import com.littlespidy.apiinspector.model.AuthTestResult_littlespidy;

/**
 * Listener interface for authentication test execution events and progress updates.
 */
public interface AuthTestProgressListener_littlespidy {

    /**
     * Fired when a test run is initiated with the total number of endpoints to test.
     */
    void onTestStarted(int totalEndpoints);

    /**
     * Fired whenever an individual endpoint test completes.
     */
    void onEndpointResult(AuthTestResult_littlespidy result, int completedCount, int totalCount);

    /**
     * Fired when an error interrupts the test suite.
     */
    void onTestError(String errorMessage);

    /**
     * Fired when the test run concludes, indicating whether it was cancelled.
     */
    void onTestFinished(boolean cancelled, int totalCompleted);
}
