// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import com.littlespidy.apiinspector.model.PostToGetTestResult_littlespidy;

/**
 * Progress callback listener for automated POST-to-GET method tampering tests.
 */
public interface PostToGetProgressListener_littlespidy {

    void onPostToGetTestCompleted(PostToGetTestResult_littlespidy result);

    void onStatusUpdate(String statusMessage, int current, int total);

    void onAllTestsCompleted();
}
