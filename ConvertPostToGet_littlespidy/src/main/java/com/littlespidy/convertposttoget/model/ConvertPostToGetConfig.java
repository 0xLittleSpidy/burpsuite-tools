package com.littlespidy.convertposttoget.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * User-configurable settings for the Convert POST to GET extension.
 *
 * @author littlespidy
 */
public class ConvertPostToGetConfig {
    private int maxConcurrentThreads = 10;
    private int delayBetweenRequestsMs = 0;
    private boolean updateContentTypeHeaders = true;
    private List<ConfiguredHeader> customHeaders = new ArrayList<>();

    public int getMaxConcurrentThreads() {
        return maxConcurrentThreads;
    }

    public void setMaxConcurrentThreads(int maxConcurrentThreads) {
        this.maxConcurrentThreads = maxConcurrentThreads;
    }

    public int getDelayBetweenRequestsMs() {
        return delayBetweenRequestsMs;
    }

    public void setDelayBetweenRequestsMs(int delayBetweenRequestsMs) {
        this.delayBetweenRequestsMs = delayBetweenRequestsMs;
    }

    public boolean isUpdateContentTypeHeaders() {
        return updateContentTypeHeaders;
    }

    public void setUpdateContentTypeHeaders(boolean updateContentTypeHeaders) {
        this.updateContentTypeHeaders = updateContentTypeHeaders;
    }

    public List<ConfiguredHeader> getCustomHeaders() {
        return customHeaders;
    }

    public void setCustomHeaders(List<ConfiguredHeader> customHeaders) {
        this.customHeaders = customHeaders != null ? new ArrayList<>(customHeaders) : new ArrayList<>();
    }
}
