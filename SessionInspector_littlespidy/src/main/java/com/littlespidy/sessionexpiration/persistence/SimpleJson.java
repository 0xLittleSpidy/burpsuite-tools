// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.persistence;

import java.util.*;

/**
 * Lightweight, zero-dependency, high-performance JSON serializer and recursive-descent parser.
 * Designed specifically for Session Inspector state persistence without external classpath dependencies.
 *
 * @author littlespidy
 */
public class SimpleJson {

    public static Object parse(String json) {
        if (json == null) return null;
        json = json.trim();
        if (json.isEmpty()) return null;
        return new Parser(json).parseValue();
    }

    public static String serialize(Object obj) {
        StringBuilder sb = new StringBuilder(4096);
        serializeValue(obj, sb, 0);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void serializeValue(Object obj, StringBuilder sb, int indent) {
        if (obj == null) {
            sb.append("null");
        } else if (obj instanceof String s) {
            sb.append('"').append(escapeString(s)).append('"');
        } else if (obj instanceof Boolean b) {
            sb.append(b);
        } else if (obj instanceof Number n) {
            sb.append(n);
        } else if (obj instanceof Map<?, ?> map) {
            serializeObject((Map<String, Object>) map, sb, indent);
        } else if (obj instanceof Collection<?> col) {
            serializeArray(col, sb, indent);
        } else if (obj instanceof Object[] arr) {
            serializeArray(Arrays.asList(arr), sb, indent);
        } else {
            sb.append('"').append(escapeString(obj.toString())).append('"');
        }
    }

    private static void serializeObject(Map<String, Object> map, StringBuilder sb, int indent) {
        if (map.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append("{\n");
        int nextIndent = indent + 1;
        int count = 0;
        int size = map.size();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            appendIndent(sb, nextIndent);
            sb.append('"').append(escapeString(entry.getKey())).append("\": ");
            serializeValue(entry.getValue(), sb, nextIndent);
            if (++count < size) {
                sb.append(',');
            }
            sb.append('\n');
        }
        appendIndent(sb, indent);
        sb.append('}');
    }

    private static void serializeArray(Collection<?> col, StringBuilder sb, int indent) {
        if (col.isEmpty()) {
            sb.append("[]");
            return;
        }
        sb.append("[\n");
        int nextIndent = indent + 1;
        int count = 0;
        int size = col.size();
        for (Object item : col) {
            appendIndent(sb, nextIndent);
            serializeValue(item, sb, nextIndent);
            if (++count < size) {
                sb.append(',');
            }
            sb.append('\n');
        }
        appendIndent(sb, indent);
        sb.append(']');
    }

    private static void appendIndent(StringBuilder sb, int level) {
        for (int i = 0; i < level; i++) {
            sb.append("  ");
        }
    }

    public static String escapeString(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    // Helper accessor methods for Map<String, Object>
    public static String getString(Map<String, Object> map, String key, String defaultVal) {
        if (map == null) return defaultVal;
        Object v = map.get(key);
        return (v instanceof String s) ? s : (v != null ? v.toString() : defaultVal);
    }

    public static long getLong(Map<String, Object> map, String key, long defaultVal) {
        if (map == null) return defaultVal;
        Object v = map.get(key);
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s) {
            try { return Long.parseLong(s); } catch (Exception ignored) {}
        }
        return defaultVal;
    }

    public static int getInt(Map<String, Object> map, String key, int defaultVal) {
        return (int) getLong(map, key, defaultVal);
    }

    public static double getDouble(Map<String, Object> map, String key, double defaultVal) {
        if (map == null) return defaultVal;
        Object v = map.get(key);
        if (v instanceof Number n) return n.doubleValue();
        if (v instanceof String s) {
            try { return Double.parseDouble(s); } catch (Exception ignored) {}
        }
        return defaultVal;
    }

    public static boolean getBoolean(Map<String, Object> map, String key, boolean defaultVal) {
        if (map == null) return defaultVal;
        Object v = map.get(key);
        if (v instanceof Boolean b) return b;
        if (v instanceof String s) return Boolean.parseBoolean(s);
        return defaultVal;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> getMap(Map<String, Object> map, String key) {
        if (map == null) return Collections.emptyMap();
        Object v = map.get(key);
        return (v instanceof Map<?, ?> m) ? (Map<String, Object>) m : Collections.emptyMap();
    }

    @SuppressWarnings("unchecked")
    public static List<Object> getList(Map<String, Object> map, String key) {
        if (map == null) return Collections.emptyList();
        Object v = map.get(key);
        return (v instanceof List<?> l) ? (List<Object>) l : Collections.emptyList();
    }

    // Parser implementation
    private static class Parser {
        private final String text;
        private int pos = 0;
        private final int length;

        public Parser(String text) {
            this.text = text;
            this.length = text.length();
        }

        public Object parseValue() {
            skipWhitespace();
            if (pos >= length) return null;

            char c = text.charAt(pos);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't' || c == 'f') return parseBoolean();
            if (c == 'n') return parseNull();
            if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();

            throw new IllegalArgumentException("Unexpected character at position " + pos + ": " + c);
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++; // skip '{'
            skipWhitespace();
            if (pos < length && text.charAt(pos) == '}') {
                pos++;
                return map;
            }

            while (pos < length) {
                skipWhitespace();
                if (pos >= length || text.charAt(pos) != '"') {
                    break;
                }
                String key = parseString();
                skipWhitespace();
                if (pos < length && text.charAt(pos) == ':') {
                    pos++;
                }
                Object val = parseValue();
                map.put(key, val);

                skipWhitespace();
                if (pos < length && text.charAt(pos) == ',') {
                    pos++;
                } else if (pos < length && text.charAt(pos) == '}') {
                    pos++;
                    break;
                }
            }
            return map;
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            pos++; // skip '['
            skipWhitespace();
            if (pos < length && text.charAt(pos) == ']') {
                pos++;
                return list;
            }

            while (pos < length) {
                Object val = parseValue();
                list.add(val);
                skipWhitespace();
                if (pos < length && text.charAt(pos) == ',') {
                    pos++;
                } else if (pos < length && text.charAt(pos) == ']') {
                    pos++;
                    break;
                }
            }
            return list;
        }

        private String parseString() {
            pos++; // skip opening '"'
            StringBuilder sb = new StringBuilder();
            while (pos < length) {
                char c = text.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\' && pos < length) {
                    char esc = text.charAt(pos++);
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 <= length) {
                                String hex = text.substring(pos, pos + 4);
                                sb.append((char) Integer.parseInt(hex, 16));
                                pos += 4;
                            }
                        }
                        default -> sb.append(esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Boolean parseBoolean() {
            if (text.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            } else if (text.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new IllegalArgumentException("Invalid boolean literal at position " + pos);
        }

        private Object parseNull() {
            if (text.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new IllegalArgumentException("Invalid null literal at position " + pos);
        }

        private Number parseNumber() {
            int start = pos;
            if (text.charAt(pos) == '-') pos++;
            boolean hasDot = false;
            boolean hasExp = false;
            while (pos < length) {
                char c = text.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                } else if (c == '.' && !hasDot) {
                    hasDot = true;
                    pos++;
                } else if ((c == 'e' || c == 'E') && !hasExp) {
                    hasExp = true;
                    pos++;
                    if (pos < length && (text.charAt(pos) == '+' || text.charAt(pos) == '-')) {
                        pos++;
                    }
                } else {
                    break;
                }
            }
            String numStr = text.substring(start, pos);
            if (hasDot || hasExp) {
                return Double.parseDouble(numStr);
            }
            return Long.parseLong(numStr);
        }

        private void skipWhitespace() {
            while (pos < length) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }
    }
}
