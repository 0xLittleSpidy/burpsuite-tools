package com.littlespidy.uploadscanner.engine;

import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Provides offset calculation and marker creation for visual editor highlighting
 * in Burp Suite's Montoya API.
 *
 * @author littlespidy
 */
public class MarkerHighlighter {

    /**
     * Result of extracting text between two markers including calculated offset ranges.
     */
    public static class ExtractionResult {
        private final boolean found;
        private final String extractedText;
        private final int startMarkerOffset;
        private final int endMarkerOffset;
        private final int contentStartOffset;
        private final int contentEndOffset;

        public ExtractionResult(boolean found, String extractedText,
                                int startMarkerOffset, int endMarkerOffset,
                                int contentStartOffset, int contentEndOffset) {
            this.found = found;
            this.extractedText = extractedText != null ? extractedText : "";
            this.startMarkerOffset = startMarkerOffset;
            this.endMarkerOffset = endMarkerOffset;
            this.contentStartOffset = contentStartOffset;
            this.contentEndOffset = contentEndOffset;
        }

        public static ExtractionResult notFound() {
            return new ExtractionResult(false, "", -1, -1, -1, -1);
        }

        public boolean isFound() {
            return found;
        }

        public String getExtractedText() {
            return extractedText;
        }

        public int getStartMarkerOffset() {
            return startMarkerOffset;
        }

        public int getEndMarkerOffset() {
            return endMarkerOffset;
        }

        public int getContentStartOffset() {
            return contentStartOffset;
        }

        public int getContentEndOffset() {
            return contentEndOffset;
        }

        public List<Marker> toMarkers() {
            if (!found || contentStartOffset < 0 || contentEndOffset <= contentStartOffset) {
                return Collections.emptyList();
            }
            try {
                return List.of(Marker.marker(contentStartOffset, contentEndOffset));
            } catch (Throwable ignored) {
                return Collections.emptyList();
            }
        }

        public List<Marker> toFullMarkers() {
            if (!found) {
                return Collections.emptyList();
            }
            List<Marker> markers = new ArrayList<>();
            if (contentStartOffset >= 0 && contentEndOffset > contentStartOffset) {
                try {
                    markers.add(Marker.marker(contentStartOffset, contentEndOffset));
                } catch (Throwable ignored) {
                    // Burp runtime factory not available
                }
            }
            return markers;
        }
    }

    /**
     * Extract string between startMarker and endMarker with precise byte/char offsets.
     */
    public static ExtractionResult extractBetweenMarkers(String content, String startMarker, String endMarker) {
        if (content == null || startMarker == null || endMarker == null ||
                startMarker.isEmpty() || endMarker.isEmpty()) {
            return ExtractionResult.notFound();
        }

        int startIdx = content.indexOf(startMarker);
        if (startIdx == -1) {
            return ExtractionResult.notFound();
        }

        int contentStart = startIdx + startMarker.length();
        int endIdx = content.indexOf(endMarker, contentStart);
        if (endIdx == -1) {
            return ExtractionResult.notFound();
        }

        String extracted = content.substring(contentStart, endIdx);
        return new ExtractionResult(true, extracted, startIdx, endIdx + endMarker.length(), contentStart, endIdx);
    }

    /**
     * Finds all occurrences of a search string within content and returns Montoya Markers.
     */
    public static List<Marker> findMarkers(String content, String search) {
        if (content == null || search == null || search.isEmpty()) {
            return Collections.emptyList();
        }

        List<Marker> markers = new ArrayList<>();
        int index = 0;
        int searchLen = search.length();

        while ((index = content.indexOf(search, index)) != -1) {
            try {
                markers.add(Marker.marker(index, index + searchLen));
            } catch (Throwable ignored) {
                // Burp runtime factory not available
            }
            index += searchLen;
        }

        return markers;
    }

    /**
     * Finds all occurrences of a search string within byte array and returns Montoya Markers.
     */
    public static List<Marker> findMarkers(byte[] contentBytes, String search) {
        if (contentBytes == null || search == null || search.isEmpty()) {
            return Collections.emptyList();
        }
        String content = new String(contentBytes, StandardCharsets.ISO_8859_1);
        return findMarkers(content, search);
    }

    /**
     * Create a single marker from start and end offsets.
     */
    public static Marker createMarker(int start, int end) {
        return Marker.marker(start, end);
    }
}
