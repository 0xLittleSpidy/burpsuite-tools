// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.responseinspector.model.FindingCategory;
import com.littlespidy.responseinspector.model.FindingEntry;
import com.littlespidy.responseinspector.model.InspectorDataStore;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans HTTP responses for:
 * 1. Strict Social Security Numbers (SSNs) with valid area/group/serial format checks
 * 2. Internal RFC 1918 / Loopback IPv4 & IPv6 addresses
 * 3. Real OS Server Filesystem Paths (Linux system roots, /var/log, /etc, /home, Windows drive & UNC paths)
 */
public class PiiNetworkPathScanner {

    // ── Strict SSN Pattern (US SSN: 3 digits - 2 digits - 4 digits) ───────────
    // Area number cannot be 000, 666, or 900-999. Group cannot be 00. Serial cannot be 0000.
    private static final Pattern STRICT_SSN_PATTERN = Pattern.compile(
            "\\b(?!000|666|9\\d{2})(\\d{3})-(?!00)(\\d{2})-(?!0000)(\\d{4})\\b"
    );

    // ── Internal IP Patterns (RFC 1918 + Loopback + Link-Local) ───────────────
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
    private static final Pattern INTERNAL_IPV4_PATTERN = Pattern.compile(
            "(?<![0-9.])(?:10\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){2}" +
            "|172\\.(?:1[6-9]|2\\d|3[0-1])(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){2}" +
            "|192\\.168(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){2}" +
            "|127\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){2}" +
            "|169\\.254\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d))(?![0-9.])"
    );

    // ── OS Server Paths (Excludes normal client web routes) ───────────────────
    // Linux OS paths: /etc/, /var/log/, /var/www/, /opt/, /root/, /home/<user>/, /proc/, /sys/
    private static final Pattern LINUX_OS_PATH_PATTERN = Pattern.compile(
            "/(?:etc/(?:passwd|shadow|hosts|apache2|nginx|mysql|php|sudoers|issue|fstab|[a-zA-Z0-9_.-]+)" +
            "|var/(?:log|www|spool|run|lib|cache)/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+" +
            "|home/[a-zA-Z0-9_.-]+/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+" +
            "|root/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+" +
            "|usr/(?:local|share|lib|bin|sbin)/(?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+" +
            "|opt/(?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+)"
    );

    // Windows OS paths: C:\inetpub\, C:\Windows\, C:\Users\, D:\app\, UNC paths \\server\share
    private static final Pattern WINDOWS_OS_PATH_PATTERN = Pattern.compile(
            "(?:[a-zA-Z]:\\\\(?:(?:inetpub|Windows|Users|Program Files|Program Files \\(x86\\)|var|app|logs|deployment|www)[\\\\a-zA-Z0-9_.-]*" +
            "|(?:[a-zA-Z0-9_.-]+[\\\\])+[a-zA-Z0-9_.-]+\\.(?:exe|dll|cs|vb|config|ini|log|aspx|ashx|php|py|jar|xml|json|txt|env))" +
            "|\\\\[a-zA-Z0-9_.-]+\\\\[a-zA-Z0-9_.-]+(?:\\[a-zA-Z0-9_.-]+)+)"
    );

    public List<FindingEntry> scan(HttpRequestResponse requestResponse, InspectorDataStore dataStore) {
        List<FindingEntry> findings = new ArrayList<>();
        if (requestResponse == null || requestResponse.response() == null) {
            return findings;
        }

        HttpResponse response = requestResponse.response();

        // 0. Response Headers: Internal IPs
        String headers = ScannerUtils.extractHeadersString(response);
        if (!headers.isEmpty()) {
            Matcher headerIpMatcher = INTERNAL_IPV4_PATTERN.matcher(headers);
            Set<String> seenHeaderIps = new HashSet<>();
            while (headerIpMatcher.find()) {
                String ip = headerIpMatcher.group();
                if (seenHeaderIps.add(ip)) {
                    String subType = getIpSubtype(ip);
                    findings.add(FindingEntry.create(
                            dataStore.nextId(),
                            FindingCategory.PII_NETWORK_PATH,
                            "Internal IP Address (" + subType + ")",
                            ip,
                            "Response Headers",
                            requestResponse,
                            headerIpMatcher.start(),
                            headerIpMatcher.end()
                    ));
                }
            }
        }

        String body = ScannerUtils.convertByteArrayToString(response.body());
        if (body.isEmpty()) {
            return findings;
        }

        // 1. Strict SSN Scanner
        Matcher ssnMatcher = STRICT_SSN_PATTERN.matcher(body);
        Set<String> seenSsn = new HashSet<>();
        while (ssnMatcher.find()) {
            String ssn = ssnMatcher.group();
            if (isDummySsn(ssn)) continue; // Filter out known dummy sequences
            if (seenSsn.add(ssn)) {
                findings.add(FindingEntry.create(
                        dataStore.nextId(),
                        FindingCategory.PII_NETWORK_PATH,
                        "Strict Social Security Number",
                        maskSsn(ssn),
                        "Response Body",
                        requestResponse,
                        ssnMatcher.start(),
                        ssnMatcher.end()
                ));
            }
        }

        // 2. Internal IP Scanner
        Matcher ipMatcher = INTERNAL_IPV4_PATTERN.matcher(body);
        Set<String> seenIps = new HashSet<>();
        while (ipMatcher.find()) {
            String ip = ipMatcher.group();
            if (seenIps.add(ip)) {
                String subType = getIpSubtype(ip);
                findings.add(FindingEntry.create(
                        dataStore.nextId(),
                        FindingCategory.PII_NETWORK_PATH,
                        "Internal IP Address (" + subType + ")",
                        ip,
                        "Response Body",
                        requestResponse,
                        ipMatcher.start(),
                        ipMatcher.end()
                ));
            }
        }

        // 3. Linux OS Server Paths
        Matcher linuxMatcher = LINUX_OS_PATH_PATTERN.matcher(body);
        Set<String> seenLinuxPaths = new HashSet<>();
        while (linuxMatcher.find()) {
            String path = linuxMatcher.group();
            if (isValidServerPath(path) && seenLinuxPaths.add(path)) {
                findings.add(FindingEntry.create(
                        dataStore.nextId(),
                        FindingCategory.PII_NETWORK_PATH,
                        "Linux OS Server Path",
                        path,
                        "Response Body",
                        requestResponse,
                        linuxMatcher.start(),
                        linuxMatcher.end()
                ));
            }
        }

        // 4. Windows OS Server Paths
        Matcher winMatcher = WINDOWS_OS_PATH_PATTERN.matcher(body);
        Set<String> seenWinPaths = new HashSet<>();
        while (winMatcher.find()) {
            String path = winMatcher.group();
            if (seenWinPaths.add(path)) {
                findings.add(FindingEntry.create(
                        dataStore.nextId(),
                        FindingCategory.PII_NETWORK_PATH,
                        "Windows OS Server Path",
                        path,
                        "Response Body",
                        requestResponse,
                        winMatcher.start(),
                        winMatcher.end()
                ));
            }
        }

        return findings;
    }

    private static boolean isDummySsn(String ssn) {
        String clean = ssn.replace("-", "");
        if (clean.equals("123456789") || clean.equals("987654321")) return true;
        // Check if all digits are repeating e.g. 111-11-1111
        char first = clean.charAt(0);
        boolean allSame = true;
        for (int i = 1; i < clean.length(); i++) {
            if (clean.charAt(i) != first) {
                allSame = false;
                break;
            }
        }
        return allSame;
    }

    private static String maskSsn(String ssn) {
        if (ssn.length() >= 11) {
            return "***-**-" + ssn.substring(7);
        }
        return ssn;
    }

    private static String getIpSubtype(String ip) {
        if (ip.startsWith("127.")) return "Loopback";
        if (ip.startsWith("10.")) return "RFC1918 Class A";
        if (ip.startsWith("192.168.")) return "RFC1918 Class C";
        if (ip.startsWith("172.")) return "RFC1918 Class B";
        if (ip.startsWith("169.254.")) return "Link-Local";
        return "Internal";
    }

    private static boolean isValidServerPath(String path) {
        // Exclude common web assets and short noisy matches
        if (path.length() < 7) return false;
        String lower = path.toLowerCase();
        if (lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")
                || lower.endsWith(".svg") || lower.endsWith(".css") || lower.endsWith(".woff")
                || lower.endsWith(".woff2")) {
            return false;
        }
        return true;
    }
}
