// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.util;

import java.io.File;

/**
 * Utility methods for operating system detection and default path resolution.
 * Plain ASCII text only.
 */
public final class OSUtils {

    private OSUtils() {}

    public static File getDefaultSqlmapOutputDir() {
        String osName = System.getProperty("os.name", "").toLowerCase();
        String userHome = System.getProperty("user.home", ".");

        if (osName.contains("win")) {
            String localAppData = System.getenv("LOCALAPPDATA");
            if (localAppData != null && !localAppData.isBlank()) {
                File dir = new File(localAppData, "sqlmap" + File.separator + "output");
                if (dir.exists()) return dir;
            }
            File fallback = new File(userHome, "AppData" + File.separator + "Local" + File.separator + "sqlmap" + File.separator + "output");
            if (fallback.exists()) return fallback;
            return new File(userHome);
        } else if (osName.contains("mac")) {
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
}
