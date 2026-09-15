// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.csp.evaluator;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Checks GitHub (https://github.com/google/csp-evaluator) for new releases of Google's CSP Evaluator
 * so users can notify the developer (littlespidy) to update the extension when Google publishes new rules.
 *
 * @author littlespidy
 */
public class GoogleCspUpdateChecker {

    public static final String EMBEDDED_VERSION = "v1.1.8";
    public static final String REPO_URL = "https://github.com/google/csp-evaluator";
    public static final String RELEASES_URL = "https://github.com/google/csp-evaluator/releases";
    private static final String GITHUB_API_URL = "https://api.github.com/repos/google/csp-evaluator/releases/latest";

    private static final Pattern TAG_PATTERN = Pattern.compile("\"tag_name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern URL_PATTERN = Pattern.compile("\"html_url\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern DATE_PATTERN = Pattern.compile("\"published_at\"\\s*:\\s*\"([^\"]+)\"");

    public record CheckResult(
        boolean success,
        boolean updateAvailable,
        String embeddedVersion,
        String latestVersion,
        String releaseUrl,
        String publishedAt,
        String errorMessage
    ) {}

    public static CheckResult performCheck() {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(6))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(GITHUB_API_URL))
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "HeaderInspector-BurpExtension")
                    .header("Accept", "application/vnd.github.v3+json")
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                String body = response.body();
                Matcher tagMatcher = TAG_PATTERN.matcher(body);
                Matcher urlMatcher = URL_PATTERN.matcher(body);
                Matcher dateMatcher = DATE_PATTERN.matcher(body);

                String latestTag = tagMatcher.find() ? tagMatcher.group(1).trim() : "";
                String releaseUrl = urlMatcher.find() ? urlMatcher.group(1).trim() : RELEASES_URL;
                String publishedAt = dateMatcher.find() ? dateMatcher.group(1).trim() : "";

                if (latestTag.isEmpty()) {
                    return new CheckResult(false, false, EMBEDDED_VERSION, "", RELEASES_URL, "", "Could not parse tag_name from GitHub API response.");
                }

                boolean updateAvailable = isNewerVersion(latestTag, EMBEDDED_VERSION);
                return new CheckResult(true, updateAvailable, EMBEDDED_VERSION, latestTag, releaseUrl, publishedAt, null);
            } else {
                return new CheckResult(false, false, EMBEDDED_VERSION, "", RELEASES_URL, "",
                        "GitHub API returned HTTP status " + response.statusCode());
            }
        } catch (Exception ex) {
            return new CheckResult(false, false, EMBEDDED_VERSION, "", RELEASES_URL, "", ex.getMessage());
        }
    }

    public static void checkForUpdatesAsync(Component parent) {
        SwingWorker<CheckResult, Void> worker = new SwingWorker<>() {
            @Override
            protected CheckResult doInBackground() {
                return performCheck();
            }

            @Override
            protected void done() {
                try {
                    CheckResult result = get();
                    showUpdateDialog(parent, result);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(parent,
                        "Error checking for updates: " + ex.getMessage(),
                        "Update Check Failed", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private static void showUpdateDialog(Component parent, CheckResult result) {
        if (!result.success()) {
            JPanel panel = new JPanel(new BorderLayout(8, 8));
            panel.add(new JLabel("<html><b>Could not check for Google CSP Evaluator updates automatically:</b><br/>"
                    + "<font color='gray'>" + escapeHtml(result.errorMessage()) + "</font><br/><br/>"
                    + "<b>Embedded Engine Version:</b> " + result.embeddedVersion() + "<br/>"
                    + "<b>Repository:</b> <a href='" + REPO_URL + "'>" + REPO_URL + "</a></html>"), BorderLayout.CENTER);

            Object[] options = {"Open Releases in Browser", "Copy Link", "Close"};
            int choice = JOptionPane.showOptionDialog(parent, panel, "Google CSP Evaluator Version Check",
                    JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[0]);

            if (choice == 0) {
                openBrowser(RELEASES_URL);
            } else if (choice == 1) {
                copyToClipboard(RELEASES_URL);
            }
            return;
        }

        if (result.updateAvailable()) {
            String msg = "<html><font size='+1' color='#D32F2F'><b>🚀 New Google CSP Evaluator Release Available!</b></font><br/><br/>"
                    + "A new version of Google CSP Evaluator has been published on GitHub:<br/>"
                    + "<b>Latest Google Release:</b> <font color='#D32F2F'><b>" + result.latestVersion() + "</b></font><br/>"
                    + "<b>Embedded Engine Version:</b> " + result.embeddedVersion() + "<br/>"
                    + (result.publishedAt().isEmpty() ? "" : "<b>Published Date:</b> " + result.publishedAt() + "<br/>")
                    + "<b>Release URL:</b> " + result.releaseUrl() + "<br/><br/>"
                    + "<i>💡 Please notify the extension developer (littlespidy) to update the inbuilt rules and allowlist bypass datasets!</i></html>";

            JPanel panel = new JPanel(new BorderLayout(8, 8));
            panel.add(new JLabel(msg), BorderLayout.CENTER);

            Object[] options = {"Open Release Page", "Copy Update Notification", "Close"};
            int choice = JOptionPane.showOptionDialog(parent, panel, "New Google CSP Release Found!",
                    JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);

            if (choice == 0) {
                openBrowser(result.releaseUrl());
            } else if (choice == 1) {
                String notification = "Hello littlespidy, Google released a new version of csp-evaluator ("
                        + result.latestVersion() + "). Please update the HeaderInspector extension! Release: " + result.releaseUrl();
                copyToClipboard(notification);
                JOptionPane.showMessageDialog(parent, "Notification copied to clipboard! You can share this with the developer.", "Copied", JOptionPane.INFORMATION_MESSAGE);
            }
        } else {
            String msg = "<html><font size='+1' color='#2E7D32'><b>✅ Google CSP Evaluator is Up-to-Date!</b></font><br/><br/>"
                    + "The embedded engine matches the latest official release from Google:<br/>"
                    + "<b>Embedded Engine Version:</b> " + result.embeddedVersion() + "<br/>"
                    + "<b>Latest GitHub Release:</b> " + result.latestVersion() + "<br/>"
                    + (result.publishedAt().isEmpty() ? "" : "<b>Published Date:</b> " + result.publishedAt() + "<br/>")
                    + "<b>GitHub Repository:</b> <a href='" + REPO_URL + "'>" + REPO_URL + "</a><br/><br/>"
                    + "All official Google security rules, strict CSP checks, syntax verifications, and JSONP/Angular bypasses are current.</html>";

            JPanel panel = new JPanel(new BorderLayout(8, 8));
            panel.add(new JLabel(msg), BorderLayout.CENTER);

            Object[] options = {"Open Repository", "OK"};
            int choice = JOptionPane.showOptionDialog(parent, panel, "Google CSP Evaluator Up-to-Date",
                    JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[1]);

            if (choice == 0) {
                openBrowser(REPO_URL);
            }
        }
    }

    public static boolean isNewerVersion(String latest, String embedded) {
        String l = latest.replaceAll("^[vV]", "").trim();
        String e = embedded.replaceAll("^[vV]", "").trim();

        String[] lParts = l.split("\\.");
        String[] eParts = e.split("\\.");
        int maxLen = Math.max(lParts.length, eParts.length);

        for (int i = 0; i < maxLen; i++) {
            int lNum = (i < lParts.length) ? parseLeadingInt(lParts[i]) : 0;
            int eNum = (i < eParts.length) ? parseLeadingInt(eParts[i]) : 0;
            if (lNum > eNum) return true;
            if (lNum < eNum) return false;
        }
        return false;
    }

    private static int parseLeadingInt(String str) {
        try {
            Matcher m = Pattern.compile("^\\d+").matcher(str);
            if (m.find()) {
                return Integer.parseInt(m.group());
            }
        } catch (Exception ignored) {}
        return 0;
    }

    private static void openBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
            }
        } catch (Exception ignored) {}
    }

    private static void copyToClipboard(String text) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        } catch (Exception ignored) {}
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
