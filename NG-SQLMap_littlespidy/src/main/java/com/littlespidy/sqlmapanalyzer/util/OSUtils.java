// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.File;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility methods for operating system detection and default path resolution.
 * Plain ASCII text only.
 */
public final class OSUtils {

    private OSUtils() {}

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    public static boolean isMac() {
        return System.getProperty("os.name", "").toLowerCase().contains("mac");
    }

    public static String cleanPath(String path) {
        if (path == null) return "";
        String trimmed = path.trim();
        if ((trimmed.startsWith("\"") && trimmed.endsWith("\"")) ||
            (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
            if (trimmed.length() >= 2) {
                trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
            }
        }
        return trimmed;
    }

    public static String getDefaultPythonBinary() {
        if (isWindows()) {
            return "python";
        }
        return "python3";
    }

    public static java.util.Map<String, String> parseHeadersFromRawRequest(byte[] rawRequest) {
        java.util.Map<String, String> map = new java.util.LinkedHashMap<>();
        if (rawRequest == null || rawRequest.length == 0) return map;

        String raw = new String(rawRequest, java.nio.charset.StandardCharsets.UTF_8);
        String[] lines = raw.split("\r?\n");
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isBlank()) break; // End of HTTP headers
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim();
                String value = line.substring(colonIdx + 1).trim();
                if (map.containsKey(name)) {
                    if ("cookie".equalsIgnoreCase(name)) {
                        map.put(name, map.get(name) + "; " + value);
                    } else {
                        map.put(name, map.get(name) + ", " + value);
                    }
                } else {
                    map.put(name, value);
                }
            }
        }
        return map;
    }

    public static HttpService createHttpServiceFromUrl(MontoyaApi api, String url) {
        if (url == null || url.isBlank()) return null;
        try {
            return HttpService.httpService(url);
        } catch (Exception ignored) {
            try {
                URI uri = URI.create(url);
                String host = uri.getHost();
                if (host != null && !host.isBlank()) {
                    boolean secure = "https".equalsIgnoreCase(uri.getScheme());
                    int port = uri.getPort();
                    if (port <= 0) {
                        port = secure ? 443 : 80;
                    }
                    return HttpService.httpService(host, port, secure);
                }
            } catch (Exception ignored2) {}
        }
        return null;
    }

    public static String resolveFullUrlFromRaw(byte[] rawRequest, String fallbackUrl) {
        if (rawRequest == null || rawRequest.length == 0) {
            return fallbackUrl != null ? fallbackUrl : "";
        }
        String text = new String(rawRequest, java.nio.charset.StandardCharsets.UTF_8);
        String[] lines = text.split("\r?\n");
        String path = "/";
        String host = "";

        if (lines.length > 0 && !lines[0].trim().isEmpty()) {
            String[] parts = lines[0].trim().split("\\s+");
            if (parts.length > 1) {
                path = parts[1];
            }
        }

        for (String line : lines) {
            if (line.toLowerCase().startsWith("host:")) {
                host = line.substring(5).trim();
                break;
            }
        }

        if (host.isEmpty()) {
            return fallbackUrl != null ? fallbackUrl : (path.startsWith("http") ? path : "");
        }

        String scheme = "http://";
        if (fallbackUrl != null && fallbackUrl.toLowerCase().startsWith("https://")) {
            scheme = "https://";
        } else if (host.contains(":443")) {
            scheme = "https://";
        }

        if (!path.startsWith("/")) {
            path = "/" + path;
        }

        return scheme + host + path;
    }

    public static String resolveFullUrl(HttpRequest request, String fallbackUrl) {
        if (request == null) {
            return fallbackUrl != null ? fallbackUrl : "";
        }

        // 1. Try attached HttpService if present
        try {
            HttpService service = request.httpService();
            if (service != null && service.host() != null && !service.host().isBlank()) {
                String host = service.host().trim();
                boolean secure = service.secure();
                int port = service.port();
                String scheme = secure ? "https://" : "http://";
                String portPart = "";
                if (secure && port > 0 && port != 443) {
                    portPart = ":" + port;
                } else if (!secure && port > 0 && port != 80) {
                    portPart = ":" + port;
                }
                String path = request.path();
                if (path == null || path.isBlank()) {
                    path = "/";
                }
                if (!path.startsWith("/")) {
                    path = "/" + path;
                }
                return scheme + host + portPart + path;
            }
        } catch (Exception ignored) {}

        // 2. Check if request.url() already contains a full URL
        try {
            String rawUrl = request.url();
            if (rawUrl != null && (rawUrl.startsWith("http://") || rawUrl.startsWith("https://"))) {
                return rawUrl;
            }
        } catch (Exception ignored) {}

        // 3. Fallback to raw bytes
        try {
            if (request.toByteArray() != null) {
                byte[] raw = request.toByteArray().getBytes();
                if (raw != null && raw.length > 0) {
                    return resolveFullUrlFromRaw(raw, fallbackUrl);
                }
            }
        } catch (Exception ignored) {}

        // 4. Fallback to Host header
        try {
            String hostHeader = request.headerValue("Host");
            if (hostHeader != null && !hostHeader.isBlank()) {
                hostHeader = hostHeader.trim();
                String scheme = (fallbackUrl != null && fallbackUrl.toLowerCase().startsWith("https://")) || hostHeader.contains(":443") ? "https://" : "http://";
                String path = request.path();
                if (path == null || path.isBlank()) {
                    path = request.url();
                }
                if (path == null || path.isBlank()) {
                    path = "/";
                }
                if (!path.startsWith("/")) {
                    path = "/" + path;
                }
                return scheme + hostHeader + path;
            }
        } catch (Exception ignored) {}

        return fallbackUrl != null ? fallbackUrl : "";
    }

    public static File getDefaultSqlmapOutputDir() {
        String userHome = System.getProperty("user.home", ".");

        if (isWindows()) {
            String localAppData = System.getenv("LOCALAPPDATA");
            if (localAppData != null && !localAppData.isBlank()) {
                File dir = new File(localAppData, "sqlmap" + File.separator + "output");
                if (dir.exists()) return dir;
            }
            File fallback = new File(userHome, "AppData" + File.separator + "Local" + File.separator + "sqlmap" + File.separator + "output");
            if (fallback.exists()) return fallback;
            return new File(userHome);
        } else if (isMac()) {
            File macDir = new File(userHome, ".local/share/sqlmap/output");
            if (macDir.exists()) return macDir;
            File macAppSupport = new File(userHome, "Library/Application Support/sqlmap/output");
            if (macAppSupport.exists()) return macAppSupport;
            return new File(userHome);
        } else {
            // Linux / Unix
            File linuxDir = new File(userHome, ".local/share/sqlmap/output");
            if (linuxDir.exists()) return linuxDir;
            return new File(userHome);
        }
    }

    public static String findSqlmapApiPath() {
        List<String> candidates = new ArrayList<>();
        String userHome = System.getProperty("user.home", ".");

        if (isWindows()) {
            String localAppData = System.getenv("LOCALAPPDATA");
            String appData = System.getenv("APPDATA");
            String programFiles = System.getenv("ProgramFiles");
            String programFilesX86 = System.getenv("ProgramFiles(x86)");

            // 1. Check C:\Python* directories (e.g. C:\Python315, C:\Python314, C:\Python312, etc.)
            for (String drive : new String[]{"C:", "D:"}) {
                File driveRoot = new File(drive + File.separator);
                if (driveRoot.exists() && driveRoot.isDirectory()) {
                    File[] pyDirs = driveRoot.listFiles((dir, name) -> name.toLowerCase().startsWith("python"));
                    if (pyDirs != null) {
                        for (File pyDir : pyDirs) {
                            candidates.add(new File(pyDir, "Lib" + File.separator + "site-packages" + File.separator + "sqlmap" + File.separator + "sqlmapapi.py").getAbsolutePath());
                            candidates.add(new File(pyDir, "sqlmapapi.py").getAbsolutePath());
                        }
                    }
                }
            }

            // 2. Check %LOCALAPPDATA%\Programs\Python\Python*
            if (localAppData != null && !localAppData.isBlank()) {
                File localPyDir = new File(localAppData, "Programs" + File.separator + "Python");
                if (localPyDir.exists() && localPyDir.isDirectory()) {
                    File[] subDirs = localPyDir.listFiles();
                    if (subDirs != null) {
                        for (File subDir : subDirs) {
                            candidates.add(new File(subDir, "Lib" + File.separator + "site-packages" + File.separator + "sqlmap" + File.separator + "sqlmapapi.py").getAbsolutePath());
                            candidates.add(new File(subDir, "sqlmapapi.py").getAbsolutePath());
                        }
                    }
                }
            }

            // 3. Check %APPDATA%\Python\Python*
            if (appData != null && !appData.isBlank()) {
                File roamingPyDir = new File(appData, "Python");
                if (roamingPyDir.exists() && roamingPyDir.isDirectory()) {
                    File[] subDirs = roamingPyDir.listFiles();
                    if (subDirs != null) {
                        for (File subDir : subDirs) {
                            candidates.add(new File(subDir, "site-packages" + File.separator + "sqlmap" + File.separator + "sqlmapapi.py").getAbsolutePath());
                        }
                    }
                }
            }

            // 4. Check Program Files
            for (String pf : new String[]{programFiles, programFilesX86}) {
                if (pf != null && !pf.isBlank()) {
                    File pfDir = new File(pf);
                    if (pfDir.exists() && pfDir.isDirectory()) {
                        File[] pyDirs = pfDir.listFiles((dir, name) -> name.toLowerCase().startsWith("python"));
                        if (pyDirs != null) {
                            for (File pyDir : pyDirs) {
                                candidates.add(new File(pyDir, "Lib" + File.separator + "site-packages" + File.separator + "sqlmap" + File.separator + "sqlmapapi.py").getAbsolutePath());
                            }
                        }
                    }
                }
            }

            // 5. User home sqlmap clone
            candidates.add(userHome + File.separator + "sqlmap" + File.separator + "sqlmapapi.py");
            candidates.add(userHome + File.separator + "AppData" + File.separator + "Local" + File.separator + "sqlmap" + File.separator + "sqlmapapi.py");
        } else {
            // Linux / macOS candidates
            candidates.add("/usr/share/sqlmap/sqlmapapi.py");
            candidates.add("/usr/local/share/sqlmap/sqlmapapi.py");
            candidates.add("/opt/sqlmap/sqlmapapi.py");
            candidates.add(userHome + "/sqlmap/sqlmapapi.py");
            candidates.add(userHome + "/.local/share/sqlmap/sqlmapapi.py");

            // Python site-packages in Linux user home
            File localLib = new File(userHome, ".local/lib");
            if (localLib.exists() && localLib.isDirectory()) {
                File[] pyVersions = localLib.listFiles((dir, name) -> name.startsWith("python"));
                if (pyVersions != null) {
                    for (File pv : pyVersions) {
                        candidates.add(new File(pv, "site-packages/sqlmap/sqlmapapi.py").getAbsolutePath());
                    }
                }
            }

            // System Python dist-packages / site-packages
            for (String sysPath : new String[]{"/usr/local/lib", "/usr/lib"}) {
                File sysLib = new File(sysPath);
                if (sysLib.exists() && sysLib.isDirectory()) {
                    File[] pyVersions = sysLib.listFiles((dir, name) -> name.startsWith("python"));
                    if (pyVersions != null) {
                        for (File pv : pyVersions) {
                            candidates.add(new File(pv, "dist-packages/sqlmap/sqlmapapi.py").getAbsolutePath());
                            candidates.add(new File(pv, "site-packages/sqlmap/sqlmapapi.py").getAbsolutePath());
                        }
                    }
                }
            }
        }

        // Check explicit candidates
        for (String c : candidates) {
            File f = new File(c);
            if (f.exists() && f.isFile()) {
                return f.getAbsolutePath();
            }
        }

        // Search PATH environment variable
        String pathEnv = System.getenv("PATH");
        if (pathEnv != null && !pathEnv.isBlank()) {
            String[] dirs = pathEnv.split(File.pathSeparator);
            for (String dir : dirs) {
                if (dir.isBlank()) continue;
                File f = new File(dir, "sqlmapapi.py");
                if (f.exists() && f.isFile()) {
                    return f.getAbsolutePath();
                }
                // Also check if PATH points to a Python root containing Lib\site-packages\sqlmap\sqlmapapi.py
                File sitePackagesPy = new File(dir, "Lib" + File.separator + "site-packages" + File.separator + "sqlmap" + File.separator + "sqlmapapi.py");
                if (sitePackagesPy.exists() && sitePackagesPy.isFile()) {
                    return sitePackagesPy.getAbsolutePath();
                }
                // Or if PATH is Python\Scripts, check sibling Lib\site-packages
                File parentSitePackages = new File(dir, ".." + File.separator + "Lib" + File.separator + "site-packages" + File.separator + "sqlmap" + File.separator + "sqlmapapi.py");
                if (parentSitePackages.exists() && parentSitePackages.isFile()) {
                    return parentSitePackages.getAbsolutePath();
                }
            }
        }

        return "";
    }
}
