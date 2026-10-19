// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.engine;

import com.littlespidy.apiinspector.model.ProbeResult_littlespidy;

/**
 * Listener interface for probing execution events and UI updates.
 */
public interface ProbeProgressListener_littlespidy {
    void onProbeStarted(int totalRequests);
    void onProbeResult(ProbeResult_littlespidy result, int completedCount, int totalCount);
    void onProbeFinished(boolean wasCancelled);
    void onProbeError(String errorMessage);
}
