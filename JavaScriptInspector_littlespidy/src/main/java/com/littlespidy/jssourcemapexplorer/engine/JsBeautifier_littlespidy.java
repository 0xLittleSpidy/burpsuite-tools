// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

/**
 * Lightweight, zero-dependency JavaScript beautifier and code formatter.
 * Formats minified, compressed, or dense JavaScript code into clean, indented,
 * and readable source text for source code inspection.
 *
 * @author littlespidy
 */
public final class JsBeautifier_littlespidy {

    private static final String INDENT = "  ";

    private JsBeautifier_littlespidy() {
        // Utility class
    }

    /**
     * Formats JavaScript code with indentation and proper line breaks.
     *
     * @param jsCode Raw JavaScript source string
     * @return Formatted, readable JavaScript code
     */
    public static String beautify(String jsCode) {
        if (jsCode == null || jsCode.isEmpty()) {
            return "";
        }

        StringBuilder out = new StringBuilder(jsCode.length() + (jsCode.length() / 4));
        int indentLevel = 0;
        int len = jsCode.length();
        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        boolean inBacktick = false;
        boolean inLineComment = false;
        boolean inBlockComment = false;
        boolean escaped = false;

        for (int i = 0; i < len; i++) {
            char c = jsCode.charAt(i);
            char next = (i + 1 < len) ? jsCode.charAt(i + 1) : '\0';
            char prev = (i > 0) ? jsCode.charAt(i - 1) : '\0';

            // Handle string escape sequences
            if (escaped) {
                out.append(c);
                escaped = false;
                continue;
            }

            if (c == '\\' && (inSingleQuote || inDoubleQuote || inBacktick)) {
                out.append(c);
                escaped = true;
                continue;
            }

            // Inside single-line comment
            if (inLineComment) {
                out.append(c);
                if (c == '\n') {
                    inLineComment = false;
                    appendIndent(out, indentLevel);
                }
                continue;
            }

            // Inside block comment
            if (inBlockComment) {
                out.append(c);
                if (prev == '*' && c == '/') {
                    inBlockComment = false;
                }
                continue;
            }

            // Inside quotes
            if (inSingleQuote) {
                out.append(c);
                if (c == '\'') {
                    inSingleQuote = false;
                }
                continue;
            }
            if (inDoubleQuote) {
                out.append(c);
                if (c == '"') {
                    inDoubleQuote = false;
                }
                continue;
            }
            if (inBacktick) {
                out.append(c);
                if (c == '`') {
                    inBacktick = false;
                }
                continue;
            }

            // Check entering comments
            if (c == '/' && next == '/') {
                inLineComment = true;
                out.append("//");
                i++;
                continue;
            }
            if (c == '/' && next == '*') {
                inBlockComment = true;
                out.append("/*");
                i++;
                continue;
            }

            // Check entering strings
            if (c == '\'') {
                inSingleQuote = true;
                out.append(c);
                continue;
            }
            if (c == '"') {
                inDoubleQuote = true;
                out.append(c);
                continue;
            }
            if (c == '`') {
                inBacktick = true;
                out.append(c);
                continue;
            }

            // Structural formatting
            switch (c) {
                case '{':
                    trimTrailingSpaces(out);
                    if (out.length() > 0 && out.charAt(out.length() - 1) != '\n' && out.charAt(out.length() - 1) != ' ') {
                        out.append(' ');
                    }
                    out.append("{\n");
                    indentLevel++;
                    appendIndent(out, indentLevel);
                    break;

                case '}':
                    trimTrailingSpaces(out);
                    if (indentLevel > 0) indentLevel--;
                    if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') {
                        out.append('\n');
                    }
                    appendIndent(out, indentLevel);
                    out.append('}');
                    if (next != ';' && next != ',' && next != ')' && next != '}') {
                        out.append('\n');
                        appendIndent(out, indentLevel);
                    }
                    break;

                case ';':
                    out.append(';');
                    trimTrailingSpaces(out);
                    if (next != '\n') {
                        out.append('\n');
                        appendIndent(out, indentLevel);
                    }
                    break;

                case ',':
                    out.append(',');
                    if (next != ' ' && next != '\n') {
                        out.append(' ');
                    }
                    break;

                case ':':
                    out.append(':');
                    if (next != ' ' && next != '\n') {
                        out.append(' ');
                    }
                    break;

                case '\n':
                case '\r':
                    trimTrailingSpaces(out);
                    if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') {
                        out.append('\n');
                        appendIndent(out, indentLevel);
                    }
                    break;

                case ' ':
                case '\t':
                    if (out.length() > 0 && out.charAt(out.length() - 1) != ' ' && out.charAt(out.length() - 1) != '\n') {
                        out.append(' ');
                    }
                    break;

                default:
                    out.append(c);
                    break;
            }
        }

        return out.toString().trim();
    }

    private static void trimTrailingSpaces(StringBuilder sb) {
        while (sb.length() > 0 && (sb.charAt(sb.length() - 1) == ' ' || sb.charAt(sb.length() - 1) == '\t')) {
            sb.deleteCharAt(sb.length() - 1);
        }
    }

    private static void appendIndent(StringBuilder sb, int level) {
        for (int i = 0; i < level; i++) {
            sb.append(INDENT);
        }
    }
}
