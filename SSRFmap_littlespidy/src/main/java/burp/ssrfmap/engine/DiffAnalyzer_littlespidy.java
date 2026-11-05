// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.engine;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DiffAnalyzer_littlespidy {

    public static class AnalysisResult {
        private final String diffSummary;
        private final String lineDiff;
        private final boolean isSignificantDiff;
        private final List<String> matchedIndicators;

        public AnalysisResult(String diffSummary, String lineDiff, boolean isSignificantDiff, List<String> matchedIndicators) {
            this.diffSummary = diffSummary;
            this.lineDiff = lineDiff;
            this.isSignificantDiff = isSignificantDiff;
            this.matchedIndicators = matchedIndicators;
        }

        public String getDiffSummary() {
            return diffSummary;
        }

        public String getLineDiff() {
            return lineDiff;
        }

        public boolean isSignificantDiff() {
            return isSignificantDiff;
        }

        public List<String> getMatchedIndicators() {
            return matchedIndicators;
        }
    }

    public static AnalysisResult analyze(
            String baselineBody,
            int baselineStatusCode,
            String responseBody,
            int responseStatusCode,
            List<String> expectedIndicators) {

        int baseLen = baselineBody != null ? baselineBody.length() : 0;
        int respLen = responseBody != null ? responseBody.length() : 0;
        int lengthDelta = respLen - baseLen;

        List<String> matched = new ArrayList<>();
        if (expectedIndicators != null && responseBody != null) {
            for (String indicator : expectedIndicators) {
                if (indicator != null && !indicator.isEmpty() && responseBody.contains(indicator)) {
                    matched.add(indicator);
                }
            }
        }

        String lineDiff = computeAddedLines(baselineBody, responseBody);
        boolean significant = !matched.isEmpty()
                || Math.abs(lengthDelta) > 50
                || baselineStatusCode != responseStatusCode;

        StringBuilder summary = new StringBuilder();
        if (lengthDelta >= 0) {
            summary.append("+").append(lengthDelta).append(" B");
        } else {
            summary.append(lengthDelta).append(" B");
        }

        if (baselineStatusCode != responseStatusCode) {
            summary.append(" [Status: ").append(responseStatusCode).append("]");
        }

        if (!matched.isEmpty()) {
            summary.append(" (Matched: ").append(String.join(", ", matched)).append(")");
        } else if (!lineDiff.isEmpty() && lineDiff.length() < 120) {
            String firstLine = lineDiff.split("\n")[0].trim();
            if (!firstLine.isEmpty()) {
                summary.append(" (").append(firstLine).append(")");
            }
        }

        return new AnalysisResult(summary.toString(), lineDiff, significant, matched);
    }

    public static String computeAddedLines(String baseline, String current) {
        if (current == null || current.isEmpty()) {
            return "";
        }
        if (baseline == null || baseline.isEmpty()) {
            return current;
        }

        Set<String> baseLines = new HashSet<>();
        for (String line : baseline.split("\r?\n")) {
            baseLines.add(line.trim());
        }

        StringBuilder diff = new StringBuilder();
        for (String line : current.split("\r?\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !baseLines.contains(trimmed)) {
                diff.append("+ ").append(line).append("\n");
            }
        }
        return diff.toString();
    }
}
