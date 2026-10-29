// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import com.littlespidy.apiinspector.model.InputValidationTestResult_littlespidy;

/**
 * Progress listener callback interface for Input Validation fuzzing tests.
 */
public interface InputValidationProgressListener_littlespidy {

    void onFuzzTestCompleted(InputValidationTestResult_littlespidy result);

    void onStatusUpdate(String statusMessage, int current, int total);

    void onAllTestsCompleted();
}
