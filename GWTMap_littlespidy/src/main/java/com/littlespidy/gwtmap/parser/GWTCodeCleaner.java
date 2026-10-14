// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.parser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Formats, retabs, decodes unicode escapes, and splits obfuscated GWT code
 * into structured lines for AST and regex analysis.
 *
 * @author littlespidy
 */
public class GWTCodeCleaner {

    private static final Pattern UNICODE_ESCAPE_PATTERN = Pattern.compile("\\\\u([0-9a-fA-F]{4})");
    private static final Pattern HEX_ESCAPE_PATTERN = Pattern.compile("\\\\x([0-9a-fA-F]{2})");

    /**
     * Decodes standard unicode escape sequences (\\uXXXX) and hex escapes (\\xXX).
     */
    public static String decodeUnicodeEscapes(String input) {
        if (input == null || !input.contains("\\")) {
            return input != null ? input : "";
        }

        Matcher matcher = UNICODE_ESCAPE_PATTERN.matcher(input);
        StringBuilder sb = new StringBuilder(input.length());
        while (matcher.find()) {
            try {
                int codePoint = Integer.parseInt(matcher.group(1), 16);
                matcher.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf((char) codePoint)));
            } catch (Exception e) {
                matcher.appendReplacement(sb, matcher.group(0));
            }
        }
        matcher.appendTail(sb);

        String stage1 = sb.toString();
        if (stage1.contains("\\x")) {
            Matcher hexMatcher = HEX_ESCAPE_PATTERN.matcher(stage1);
            StringBuilder sbHex = new StringBuilder(stage1.length());
            while (hexMatcher.find()) {
                try {
                    int codePoint = Integer.parseInt(hexMatcher.group(1), 16);
                    hexMatcher.appendReplacement(sbHex, Matcher.quoteReplacement(String.valueOf((char) codePoint)));
                } catch (Exception e) {
                    hexMatcher.appendReplacement(sbHex, hexMatcher.group(0));
                }
            }
            hexMatcher.appendTail(sbHex);
            return sbHex.toString();
        }

        return stage1;
    }

    /**
     * Updates indentation based on curly brace nesting depth.
     */
    public static String retab(String code) {
        if (code == null) return "";
        StringBuilder tabbed = new StringBuilder(code.length());
        int tabs = 0;
        String[] lines = code.split("\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.equals("}") || trimmed.startsWith("}") || trimmed.equals("});")) {
                tabs = Math.max(0, tabs - 1);
            }

            for (int i = 0; i < tabs; i++) {
                tabbed.append("\t");
            }
            tabbed.append(line).append("\n");

            if (trimmed.endsWith("{")) {
                tabs++;
            }
        }
        return tabbed.toString();
    }

    /**
     * Cleans and reformats code according to its classification type.
     */
    public static List<String> cleanCode(String code, GWTClassifier.CodeType codeType) {
        if (code == null) return new ArrayList<>();

        if (codeType == GWTClassifier.CodeType.BOOTSTRAP_CLEAN
                || codeType == GWTClassifier.CodeType.PERMUTATION_CLEAN) {
            return new ArrayList<>(Arrays.asList(code.split("\n")));
        }

        if (codeType == GWTClassifier.CodeType.BOOTSTRAP_OBFUSCATED) {
            code = code.replace("\\", "\\\\");
        }

        // Break statements onto separate lines: { -> {\n, } -> \n}\n, ; -> ;\n
        StringBuilder formatted = new StringBuilder(code.length() * 2);
        char[] chars = code.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];
            if (c == '{') {
                formatted.append("{\n");
            } else if (c == '}') {
                formatted.append("\n}\n");
            } else if (c == ';') {
                formatted.append(";\n");
            } else {
                formatted.append(c);
            }
        }

        String decoded = decodeUnicodeEscapes(formatted.toString());
        String tabbed = retab(decoded);

        String[] rawLines = tabbed.split("\n");
        List<String> result = new ArrayList<>(rawLines.length);
        for (String line : rawLines) {
            result.add(line);
        }
        return result;
    }
}
