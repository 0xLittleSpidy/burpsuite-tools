package com.littlespidy.uploadscanner.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.uploadscanner.model.ReDownloaderConfig;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Core engine for ReDownloader URL parsing, marker offset calculation,
 * and redownload request generation/execution.
 *
 * @author littlespidy
 */
public class ReDownloaderEngine {
    private final MontoyaApi api;
    private final ReDownloaderConfig config;
    private final Random random = new Random();

    public ReDownloaderEngine(MontoyaApi api, ReDownloaderConfig config) {
        this.api = api;
        this.config = config;
    }

    /**
     * Resolves placeholders (${FILENAME}, ${FILENAME_NO_EXT}, ${ORIG_EXT}, ${RANDOMIZE}) in a pattern.
     */
    public String resolvePlaceholders(String pattern, String filename) {
        if (pattern == null || pattern.isEmpty()) {
            return "";
        }
        if (filename == null) {
            filename = "test.jpg";
        }

        String nameWithoutExt = filename;
        String ext = "";
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex > 0) {
            nameWithoutExt = filename.substring(0, dotIndex);
            ext = filename.substring(dotIndex + 1);
        }

        String encodedFilename = URLEncoder.encode(filename, StandardCharsets.UTF_8).replace("+", "%20");
        String encodedNameWithoutExt = URLEncoder.encode(nameWithoutExt, StandardCharsets.UTF_8).replace("+", "%20");

        String result = pattern
                .replace(ReDownloaderConfig.MARKER_FILENAME, filename)
                .replace("${ENCODED_FILENAME}", encodedFilename)
                .replace(ReDownloaderConfig.MARKER_FILENAME_NO_EXT, nameWithoutExt)
                .replace("${ENCODED_FILENAME_NO_EXT}", encodedNameWithoutExt)
                .replace(ReDownloaderConfig.MARKER_ORIG_EXT, ext);

        if (result.contains(ReDownloaderConfig.MARKER_RANDOMIZE)) {
            long randNum = 100000000000L + (long) (random.nextDouble() * 899999999999L);
            result = result.replace(ReDownloaderConfig.MARKER_RANDOMIZE, String.valueOf(randNum));
        }

        return result;
    }

    /**
     * Parses the download URL from the response using start/end markers or static URL.
     */
    public MarkerHighlighter.ExtractionResult parseDownloadUrl(String responseContent, String sentFilename) {
        if (!config.isEnabled()) {
            return MarkerHighlighter.ExtractionResult.notFound();
        }

        // 1. Start / End Marker parsing
        if (!config.getStartMarker().isEmpty() && !config.getEndMarker().isEmpty()) {
            if (responseContent == null || responseContent.isEmpty()) {
                return MarkerHighlighter.ExtractionResult.notFound();
            }

            String startMarker = resolvePlaceholders(config.getStartMarker(), sentFilename);
            String endMarker = resolvePlaceholders(config.getEndMarker(), sentFilename);

            MarkerHighlighter.ExtractionResult extraction =
                    MarkerHighlighter.extractBetweenMarkers(responseContent, startMarker, endMarker);

            if (extraction.isFound()) {
                String rawUrl = extraction.getExtractedText();
                if (config.isReplaceBackslash()) {
                    rawUrl = rawUrl.replace("\\/", "/");
                }

                String prefix = resolvePlaceholders(config.getUrlPrefix(), sentFilename);
                String suffix = resolvePlaceholders(config.getUrlSuffix(), sentFilename);
                String finalUrl = prefix + rawUrl + suffix;

                return new MarkerHighlighter.ExtractionResult(
                        true,
                        finalUrl,
                        extraction.getStartMarkerOffset(),
                        extraction.getEndMarkerOffset(),
                        extraction.getContentStartOffset(),
                        extraction.getContentEndOffset()
                );
            }
        }

        // 2. Static URL alternative
        if (!config.getStaticUrl().isEmpty()) {
            String staticUrl = resolvePlaceholders(config.getStaticUrl(), sentFilename);
            return new MarkerHighlighter.ExtractionResult(true, staticUrl, 0, 0, 0, staticUrl.length());
        }

        return MarkerHighlighter.ExtractionResult.notFound();
    }

    /**
     * Constructs a GET redownload request targeting the parsed URL.
     */
    public HttpRequest buildRedownloadRequest(HttpRequest baseRequest, String parsedUrl) {
        if (parsedUrl == null || parsedUrl.isEmpty()) {
            return null;
        }

        if (parsedUrl.startsWith("http://") || parsedUrl.startsWith("https://")) {
            return HttpRequest.httpRequestFromUrl(parsedUrl);
        }

        HttpService service = baseRequest.httpService();
        String normalizedPath = parsedUrl.startsWith("/") ? parsedUrl : "/" + parsedUrl;

        return HttpRequest.httpRequest(service, "GET " + normalizedPath + " HTTP/1.1\r\n" +
                "Host: " + service.host() + "\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n" +
                "Accept: */*\r\n" +
                "Connection: close\r\n\r\n");
    }

    /**
     * Executes the redownload HTTP request and wraps it with markers.
     */
    public HttpRequestResponse executeRedownload(HttpRequest redownloadRequest, String searchPayload) {
        if (redownloadRequest == null) {
            return null;
        }

        HttpRequestResponse responsePair = api.http().sendRequest(redownloadRequest);
        if (responsePair != null && responsePair.hasResponse() && searchPayload != null && !searchPayload.isEmpty()) {
            HttpResponse resp = responsePair.response();
            List<Marker> respMarkers = MarkerHighlighter.findMarkers(resp.bodyToString(), searchPayload);
            if (!respMarkers.isEmpty()) {
                responsePair = responsePair.withResponseMarkers(respMarkers);
            }
        }
        return responsePair;
    }

    /**
     * Executes optional preflight request if configured.
     */
    public HttpRequestResponse executePreflight(HttpRequest baseRequest) {
        if (!config.isEnabled() || config.getPreflightUrl().isEmpty()) {
            return null;
        }

        String preflightUrl = resolvePlaceholders(config.getPreflightUrl(), null);
        HttpRequest preflightReq;
        if (preflightUrl.startsWith("http://") || preflightUrl.startsWith("https://")) {
            preflightReq = HttpRequest.httpRequestFromUrl(preflightUrl);
        } else {
            HttpService service = baseRequest.httpService();
            String path = preflightUrl.startsWith("/") ? preflightUrl : "/" + preflightUrl;
            preflightReq = HttpRequest.httpRequest(service, "GET " + path + " HTTP/1.1\r\n" +
                    "Host: " + service.host() + "\r\n" +
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
                    "Accept: */*\r\n" +
                    "Connection: close\r\n\r\n");
        }

        return api.http().sendRequest(preflightReq);
    }
}
