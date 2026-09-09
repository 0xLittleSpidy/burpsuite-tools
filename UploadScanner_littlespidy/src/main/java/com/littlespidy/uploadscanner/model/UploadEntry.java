package com.littlespidy.uploadscanner.model;

import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Represents an entry in the "Done Uploads" execution activity log.
 *
 * @author littlespidy
 */
public class UploadEntry {
    private final int id;
    private final StageType stage;
    private final String method;
    private final short statusCode;
    private final String payloadName;
    private final int responseLength;
    private final String url;
    private final HttpRequestResponse requestResponse;
    private final String extractedMarkerText;
    private final List<Marker> responseMarkers;
    private final List<Marker> requestMarkers;
    private final long timestamp;

    public UploadEntry(int id,
                       StageType stage,
                       String method,
                       short statusCode,
                       String payloadName,
                       int responseLength,
                       String url,
                       HttpRequestResponse requestResponse,
                       String extractedMarkerText,
                       List<Marker> responseMarkers,
                       List<Marker> requestMarkers) {
        this.id = id;
        this.stage = stage;
        this.method = method != null ? method : "GET";
        this.statusCode = statusCode;
        this.payloadName = payloadName != null ? payloadName : "";
        this.responseLength = responseLength;
        this.url = url != null ? url : "";
        this.requestResponse = requestResponse;
        this.extractedMarkerText = extractedMarkerText != null ? extractedMarkerText : "";
        this.responseMarkers = responseMarkers != null ? new ArrayList<>(responseMarkers) : Collections.emptyList();
        this.requestMarkers = requestMarkers != null ? new ArrayList<>(requestMarkers) : Collections.emptyList();
        this.timestamp = System.currentTimeMillis();
    }

    public int getId() {
        return id;
    }

    public StageType getStage() {
        return stage;
    }

    public String getMethod() {
        return method;
    }

    public short getStatusCode() {
        return statusCode;
    }

    public String getPayloadName() {
        return payloadName;
    }

    public int getResponseLength() {
        return responseLength;
    }

    public String getUrl() {
        return url;
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public String getExtractedMarkerText() {
        return extractedMarkerText;
    }

    public List<Marker> getResponseMarkers() {
        return Collections.unmodifiableList(responseMarkers);
    }

    public List<Marker> getRequestMarkers() {
        return Collections.unmodifiableList(requestMarkers);
    }

    public long getTimestamp() {
        return timestamp;
    }
}
