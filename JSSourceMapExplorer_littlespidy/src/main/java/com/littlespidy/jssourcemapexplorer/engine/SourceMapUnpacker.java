// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.UnpackedProject;
import com.littlespidy.jssourcemapexplorer.model.UnpackedSourceFile;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses SourceMap v3 JSON documents and inline base64 data URIs,
 * normalizes source file paths, and reconstructs the full source code project.
 *
 * @author littlespidy
 */
public class SourceMapUnpacker {

    public static UnpackedProject unpack(String sourceMapUrl, String mapJsonContent) {
        if (mapJsonContent == null || mapJsonContent.trim().isEmpty()) {
            return null;
        }

        String rawJson = mapJsonContent.trim();

        // If Base64 string, decode it
        if (!rawJson.startsWith("{") && !rawJson.startsWith("[")) {
            try {
                byte[] decoded = Base64.getDecoder().decode(rawJson);
                rawJson = new String(decoded, StandardCharsets.UTF_8);
            } catch (Exception ignored) {}
        }

        List<String> sources = extractStringArray(rawJson, "sources");
        List<String> sourcesContent = extractStringArray(rawJson, "sourcesContent");

        if (sources.isEmpty()) {
            return null;
        }

        UnpackedProject project = new UnpackedProject(sourceMapUrl);

        for (int i = 0; i < sources.size(); i++) {
            String rawPath = sources.get(i);
            String content = (sourcesContent.size() > i && sourcesContent.get(i) != null)
                ? sourcesContent.get(i)
                : "// [SourceMap content not embedded for this file]";

            String normalizedPath = normalizeSourcePath(rawPath);
            String fileName = extractFileName(normalizedPath);

            int lineCount = content.split("\r?\n").length;
            int sizeBytes = content.getBytes(StandardCharsets.UTF_8).length;

            var miningResult = SecretAndEndpointMiner.mine(normalizedPath, "SourceMap", content);

            UnpackedSourceFile file = new UnpackedSourceFile(
                normalizedPath,
                fileName,
                content,
                lineCount,
                sizeBytes,
                miningResult.secrets(),
                miningResult.endpoints(),
                miningResult.cloudUrls(),
                miningResult.dependencies()
            );

            project.addFile(file);
        }

        return project;
    }

    public static String normalizeSourcePath(String rawPath) {
        if (rawPath == null || rawPath.trim().isEmpty()) return "unnamed_source.js";

        String path = rawPath.trim();

        // Remove known protocol / bundler prefixes
        String[] prefixes = {
            "webpack:///",
            "webpack://",
            "webpack-internal:///",
            "webpack-internal://",
            "vite:///",
            "vite://",
            "turbopack:///",
            "turbopack://",
            "rollup:///",
            "rollup://",
            "file:///",
            "file://"
        };

        for (String p : prefixes) {
            if (path.startsWith(p)) {
                path = path.substring(p.length());
                break;
            }
        }

        // Clean relative dots and leading slashes
        path = path.replaceAll("^\\.+/", "");
        path = path.replaceAll("^/+", "");
        path = path.replace('\\', '/');

        // Clean query strings or webpack hash suffixes (e.g. ?a1b2 or ?[hash])
        int qIdx = path.indexOf('?');
        if (qIdx != -1) {
            path = path.substring(0, qIdx);
        }

        if (path.isEmpty()) {
            return "root_source.js";
        }

        return path;
    }

    private static String extractFileName(String path) {
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash != -1 && lastSlash < path.length() - 1) {
            return path.substring(lastSlash + 1);
        }
        return path;
    }

    /**
     * Extracts a JSON string array from the raw JSON payload safely without external dependencies.
     */
    private static List<String> extractStringArray(String json, String key) {
        List<String> list = new ArrayList<>();
        Pattern keyPattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\[");
        Matcher m = keyPattern.matcher(json);
        if (!m.find()) {
            return list;
        }

        int startIdx = m.end();
        int bracketDepth = 1;
        boolean inString = false;
        boolean escape = false;
        StringBuilder currentToken = new StringBuilder();

        for (int i = startIdx; i < json.length(); i++) {
            char c = json.charAt(i);

            if (escape) {
                if (inString) {
                    if (c == 'n') currentToken.append('\n');
                    else if (c == 'r') currentToken.append('\r');
                    else if (c == 't') currentToken.append('\t');
                    else if (c == 'b') currentToken.append('\b');
                    else if (c == 'f') currentToken.append('\f');
                    else if (c == '"') currentToken.append('"');
                    else if (c == '\\') currentToken.append('\\');
                    else if (c == '/') currentToken.append('/');
                    else if (c == 'u' && i + 4 < json.length()) {
                        try {
                            String hex = json.substring(i + 1, i + 5);
                            currentToken.append((char) Integer.parseInt(hex, 16));
                            i += 4;
                        } catch (Exception ex) {
                            currentToken.append(c);
                        }
                    } else {
                        currentToken.append(c);
                    }
                }
                escape = false;
                continue;
            }

            if (c == '\\') {
                escape = true;
                continue;
            }

            if (c == '"') {
                inString = !inString;
                if (!inString) {
                    list.add(currentToken.toString());
                    currentToken.setLength(0);
                }
                continue;
            }

            if (inString) {
                currentToken.append(c);
                continue;
            }

            if (c == '[') {
                bracketDepth++;
            } else if (c == ']') {
                bracketDepth--;
                if (bracketDepth == 0) {
                    break;
                }
            } else if (c == 'n' && i + 3 < json.length() && json.substring(i, i + 4).equals("null")) {
                list.add(null);
                i += 3;
            }
        }

        return list;
    }
}
