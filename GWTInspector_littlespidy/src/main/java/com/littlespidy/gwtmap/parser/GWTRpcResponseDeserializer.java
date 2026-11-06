// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.parser;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.littlespidy.gwtmap.model.GWTRpcResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure Java parser for decoding GWT-RPC wire format server responses.
 * Parses //OK (Success) and //EX (Exception) payloads into human-readable AST and tables.
 *
 * @author littlespidy
 */
public class GWTRpcResponseDeserializer {

    private static final Pattern TYPE_SIGNATURE_PATTERN = Pattern.compile("^[a-zA-Z_$][a-zA-Z0-9_$]*(\\.[a-zA-Z_$][a-zA-Z0-9_$]*)+/[0-9]+$");

    public static boolean isGwtResponse(String responseBody) {
        if (responseBody == null || responseBody.isBlank()) return false;
        String trimmed = responseBody.trim();
        return trimmed.startsWith("//OK") || trimmed.startsWith("//EX")
                || trimmed.contains("//OK[") || trimmed.contains("//EX[");
    }

    public static GWTRpcResponse deserialize(String responseBody) {
        GWTRpcResponse resp = new GWTRpcResponse();
        if (responseBody == null || responseBody.isBlank()) {
            resp.setParseError("Empty response body");
            return resp;
        }

        String raw = responseBody.trim();
        resp.setRawResponse(raw);

        // 1. Determine Status
        if (raw.startsWith("//OK") || raw.contains("//OK[")) {
            resp.setStatus(GWTRpcResponse.ResponseStatus.SUCCESS);
        } else if (raw.startsWith("//EX") || raw.contains("//EX[")) {
            resp.setStatus(GWTRpcResponse.ResponseStatus.EXCEPTION);
        } else {
            resp.setStatus(GWTRpcResponse.ResponseStatus.UNKNOWN);
        }

        // 2. Extract Bracketed Array Payload
        int openBracket = raw.indexOf('[');
        int closeBracket = raw.lastIndexOf(']');

        if (openBracket == -1 || closeBracket <= openBracket) {
            resp.setFormattedSummary(buildFallbackSummary(resp));
            return resp;
        }

        String jsonArrayStr = raw.substring(openBracket, closeBracket + 1);

        try {
            JsonElement root = JsonParser.parseString(jsonArrayStr);
            if (!root.isJsonArray()) {
                resp.setParseError("Payload is not a valid JSON array");
                resp.setFormattedSummary(buildFallbackSummary(resp));
                return resp;
            }

            JsonArray array = root.getAsJsonArray();
            List<String> stringTable = new ArrayList<>();
            List<Object> tokens = new ArrayList<>();

            // 3. Parse Stream Version and Flags if present
            int ptr = 0;
            if (ptr < array.size() && array.get(ptr).isJsonPrimitive() && array.get(ptr).getAsJsonPrimitive().isNumber()) {
                resp.setStreamVersion(array.get(ptr++).getAsInt());
            }
            if (ptr < array.size() && array.get(ptr).isJsonPrimitive() && array.get(ptr).getAsJsonPrimitive().isNumber()) {
                resp.setFlags(array.get(ptr++).getAsInt());
            }

            // 4. Extract String Table
            // GWT responses typically format string tables as an embedded JSON Array: [v, flags, ["str1", "str2", ...], ...]
            if (ptr < array.size() && array.get(ptr).isJsonArray()) {
                JsonArray strArr = array.get(ptr++).getAsJsonArray();
                for (JsonElement el : strArr) {
                    stringTable.add(el.isJsonPrimitive() ? el.getAsString() : el.toString());
                }
            } else if (ptr < array.size() && array.get(ptr).isJsonPrimitive() && array.get(ptr).getAsJsonPrimitive().isNumber()) {
                // Alternative format: count followed by elements
                int count = array.get(ptr++).getAsInt();
                for (int i = 0; i < count && ptr < array.size(); i++) {
                    JsonElement el = array.get(ptr++);
                    stringTable.add(el.isJsonPrimitive() ? el.getAsString() : el.toString());
                }
            }

            resp.setStringTable(stringTable);

            // 5. Remaining tokens are payload indices / primitives
            while (ptr < array.size()) {
                JsonElement el = array.get(ptr++);
                if (el.isJsonPrimitive()) {
                    if (el.getAsJsonPrimitive().isNumber()) {
                        tokens.add(el.getAsInt());
                    } else if (el.getAsJsonPrimitive().isBoolean()) {
                        tokens.add(el.getAsBoolean());
                    } else {
                        tokens.add(el.getAsString());
                    }
                } else {
                    tokens.add(el.toString());
                }
            }
            resp.setPayloadTokens(tokens);

            // 6. Analyze Types and Values
            classifyResponseElements(resp, stringTable);

            // 7. Build Human-Readable Formatted Summary
            resp.setFormattedSummary(buildStructuredSummary(resp));

        } catch (Throwable t) {
            resp.setParseError("Error parsing GWT response: " + t.getMessage());
            resp.setFormattedSummary(buildFallbackSummary(resp));
        }

        return resp;
    }

    private static void classifyResponseElements(GWTRpcResponse resp, List<String> stringTable) {
        for (String item : stringTable) {
            if (item == null || item.isEmpty()) continue;

            if (isTypeSignature(item)) {
                if (resp.getReturnType().isEmpty()) {
                    resp.setReturnType(cleanType(item));
                }
                if (resp.isException() && isExceptionType(item) && resp.getExceptionType().isEmpty()) {
                    resp.setExceptionType(cleanType(item));
                }
            } else {
                resp.addExtractedValue(item);
                if (resp.isException() && resp.getExceptionMessage().isEmpty() && !item.isBlank()) {
                    resp.setExceptionMessage(item);
                }
            }
        }
    }

    public static boolean isTypeSignature(String str) {
        if (str == null) return false;
        return TYPE_SIGNATURE_PATTERN.matcher(str).matches() || str.contains("/");
    }

    public static boolean isExceptionType(String str) {
        if (str == null) return false;
        String lower = str.toLowerCase();
        return lower.contains("exception") || lower.contains("throwable") || lower.contains("error");
    }

    public static String cleanType(String fullType) {
        if (fullType == null) return "";
        int slash = fullType.indexOf('/');
        return slash != -1 ? fullType.substring(0, slash) : fullType;
    }

    private static String buildStructuredSummary(GWTRpcResponse resp) {
        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        if (resp.isSuccess()) {
            sb.append(" GWT-RPC RESPONSE STATUS: SUCCESS (//OK)\n");
        } else if (resp.isException()) {
            sb.append(" GWT-RPC RESPONSE STATUS: EXCEPTION (//EX)\n");
        } else {
            sb.append(" GWT-RPC RESPONSE STATUS: UNKNOWN\n");
        }
        sb.append("================================================================================\n\n");

        if (resp.getStreamVersion() != -1) {
            sb.append("Stream Version : ").append(resp.getStreamVersion()).append("\n");
        }
        sb.append("RPC Flags      : 0x").append(Integer.toHexString(resp.getFlags())).append("\n");

        if (resp.isException()) {
            sb.append("Exception Class: ").append(!resp.getExceptionType().isEmpty() ? resp.getExceptionType() : "Unknown Exception").append("\n");
            if (!resp.getExceptionMessage().isEmpty()) {
                sb.append("Error Message  : ").append(resp.getExceptionMessage()).append("\n");
            }
        } else if (!resp.getReturnType().isEmpty()) {
            sb.append("Return Type    : ").append(resp.getReturnType()).append("\n");
        }

        sb.append("\n--------------------------------------------------------------------------------\n");
        sb.append(" Extracted Values & Objects\n");
        sb.append("--------------------------------------------------------------------------------\n");

        if (resp.getExtractedValues().isEmpty()) {
            sb.append(" [No readable string values found in string table]\n");
        } else {
            int idx = 1;
            for (String val : resp.getExtractedValues()) {
                sb.append(String.format(" [%02d] %s\n", idx++, val));
            }
        }

        sb.append("\n--------------------------------------------------------------------------------\n");
        sb.append(" String Table (").append(resp.getStringTable().size()).append(" entries)\n");
        sb.append("--------------------------------------------------------------------------------\n");

        if (resp.getStringTable().isEmpty()) {
            sb.append(" [String table empty]\n");
        } else {
            for (int i = 0; i < resp.getStringTable().size(); i++) {
                String str = resp.getStringTable().get(i);
                String tag = isTypeSignature(str) ? "[Type]" : "[Value]";
                sb.append(String.format("  #%-3d %-8s %s\n", (i + 1), tag, str));
            }
        }

        if (!resp.getPayloadTokens().isEmpty()) {
            sb.append("\n--------------------------------------------------------------------------------\n");
            sb.append(" Payload Tokens / Indices\n");
            sb.append("--------------------------------------------------------------------------------\n");
            sb.append(" ").append(resp.getPayloadTokens().toString()).append("\n");
        }

        return sb.toString();
    }

    private static String buildFallbackSummary(GWTRpcResponse resp) {
        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        sb.append(" GWT-RPC RESPONSE (RAW FALLBACK)\n");
        sb.append("================================================================================\n\n");
        if (!resp.getParseError().isEmpty()) {
            sb.append("Note: ").append(resp.getParseError()).append("\n\n");
        }
        sb.append("Original Payload:\n").append(resp.getRawResponse()).append("\n");
        return sb.toString();
    }
}
