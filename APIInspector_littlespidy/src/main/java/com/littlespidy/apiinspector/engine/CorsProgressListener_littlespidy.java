// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import com.littlespidy.apiinspector.model.CorsTestResult_littlespidy;

/**
 * Progress listener callback interface for CORS tests.
 */
public interface CorsProgressListener_littlespidy {

    void onCorsTestCompleted(CorsTestResult_littlespidy result);

    void onStatusUpdate(String statusMessage, int current, int total);

    void onAllTestsCompleted();
}
