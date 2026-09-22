// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.activescansessionkeeper.util;

import java.awt.*;
import java.io.File;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utility for launching an isolated browser session pre-configured to route
 * all traffic through Burp Proxy.
 *
 * @author littlespidy
 */
public class BrowserLauncher {

    private static final List<String> CANDIDATE_BINARIES = Arrays.asList(
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "brave-browser",
            "microsoft-edge",
            "msedge"
    );

    /**
     * Launches a browser pointing to the target URL.
     * Prefers Chromium-based browsers with proxy flags (--proxy-server=http://host:port);
     * falls back to the system's default browser if no Chromium binary is found.
     *
     * @param targetUrl target login/auth URL
     * @param proxyHost proxy host (e.g. "127.0.0.1")
     * @param proxyPort proxy port (e.g. 8080)
     * @return status message describing how the browser was launched
     */
    public static String launchBrowser(String targetUrl, String proxyHost, int proxyPort) {
        String safeUrl = (targetUrl != null && !targetUrl.trim().isEmpty()) ? targetUrl.trim() : "http://" + proxyHost + ":" + proxyPort;

        // 1. Try launching Chromium/Chrome with dedicated proxy flags
        String binary = findChromiumBinary();
        if (binary != null) {
            try {
                String tempProfile = System.getProperty("java.io.tmpdir") + File.separator + "burp-session-browser-" + System.currentTimeMillis();
                List<String> cmd = new ArrayList<>();
                cmd.add(binary);
                cmd.add("--proxy-server=http://" + proxyHost + ":" + proxyPort);
                cmd.add("--ignore-certificate-errors");
                cmd.add("--user-data-dir=" + tempProfile);
                cmd.add("--no-first-run");
                cmd.add("--no-default-browser-check");
                cmd.add(safeUrl);

                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.start();
                return "Launched proxied browser (" + binary + ") pointing to " + safeUrl;
            } catch (Exception ignored) {}
        }

        // 2. Fallback to Desktop.getDesktop().browse()
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(safeUrl));
                return "Opened default system browser to " + safeUrl + ". (Make sure it routes via 127.0.0.1:" + proxyPort + ")";
            }
        } catch (Exception ignored) {}

        // 3. Fallback to xdg-open on Linux
        try {
            ProcessBuilder pb = new ProcessBuilder("xdg-open", safeUrl);
            pb.start();
            return "Opened URL via xdg-open: " + safeUrl;
        } catch (Exception e) {
            return "Could not automatically launch browser. Please open Burp's built-in browser (Proxy -> Open browser) or visit: " + safeUrl;
        }
    }

    private static String findChromiumBinary() {
        for (String candidate : CANDIDATE_BINARIES) {
            try {
                Process p = new ProcessBuilder("which", candidate).start();
                if (p.waitFor() == 0) {
                    return candidate;
                }
            } catch (Exception ignored) {}
        }
        return null;
    }
}
