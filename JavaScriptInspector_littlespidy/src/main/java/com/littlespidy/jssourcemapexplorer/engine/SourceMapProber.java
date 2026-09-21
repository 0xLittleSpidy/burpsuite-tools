// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.ActiveProbeStatus;
import com.littlespidy.jssourcemapexplorer.model.JsFileEntry;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Dispatches active HTTP probes for unlinked .map files (e.g. script.js -> script.js.map)
 * and preserves the Source Map's raw HttpRequest and HttpResponse.
 *
 * @author littlespidy
 */
public class SourceMapProber {

    private final MontoyaApi api;

    public SourceMapProber(MontoyaApi api) {
        this.api = api;
    }

    public boolean probe(JsFileEntry entry) {
        if (entry == null || entry.getUrl() == null) {
            return false;
        }

        entry.setActiveProbeStatus(ActiveProbeStatus.PROBING);

        String targetMapUrl = entry.getSourceMapLocation();
        if (targetMapUrl == null || targetMapUrl.trim().isEmpty() || targetMapUrl.startsWith("data:")) {
            // Construct default probe URL: append .map to JS URL (cleaning query string if present)
            String baseUrl = entry.getUrl();
            int qIdx = baseUrl.indexOf('?');
            if (qIdx != -1) {
                targetMapUrl = baseUrl.substring(0, qIdx) + ".map";
            } else {
                targetMapUrl = baseUrl + ".map";
            }
        }

        try {
            HttpRequest probeReq = HttpRequest.httpRequestFromUrl(targetMapUrl);
            HttpRequestResponse probeRr = api.http().sendRequest(probeReq);

            if (probeRr.hasResponse()) {
                HttpResponse resp = probeRr.response();
                entry.setSourceMapRequest(probeRr.request());
                entry.setSourceMapResponse(resp);

                int status = resp.statusCode();
                String body = resp.bodyToString();

                if (status == 200 && body != null && (body.contains("\"version\"") || body.contains("\"sources\""))) {
                    entry.setActiveProbeStatus(ActiveProbeStatus.PASS);
                    entry.setSourceMapLocation(targetMapUrl);
                    return true;
                } else {
                    entry.setActiveProbeStatus(ActiveProbeStatus.FAIL);
                    return false;
                }
            }
        } catch (Exception ex) {
            api.logging().logToError("SourceMap probe failed for " + targetMapUrl + ": " + ex.getMessage());
            entry.setActiveProbeStatus(ActiveProbeStatus.FAIL);
        }

        entry.setActiveProbeStatus(ActiveProbeStatus.FAIL);
        return false;
    }

    public String fetchMapContent(JsFileEntry entry, String mapUrl) {
        if (mapUrl == null || mapUrl.trim().isEmpty()) return null;

        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(mapUrl);
            HttpRequestResponse rr = api.http().sendRequest(req);
            if (rr.hasResponse()) {
                if (entry != null) {
                    entry.setSourceMapRequest(rr.request());
                    entry.setSourceMapResponse(rr.response());
                }
                if (rr.response().statusCode() == 200) {
                    return rr.response().bodyToString();
                }
            }
        } catch (Exception ex) {
            api.logging().logToError("Failed to fetch map content from " + mapUrl + ": " + ex.getMessage());
        }

        return null;
    }
}
