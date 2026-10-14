// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.parser;

import com.littlespidy.gwtmap.model.GWTRpcParameter;
import com.littlespidy.gwtmap.model.GWTRpcPayload;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Pure Java deserializer decoding raw GWT-RPC wire format requests into
 * a structured AST of services, methods, parameters, and fuzzable offsets.
 * Ports and enhances GWTParser from GDS Penetration Testing Toolset and GWTab.
 *
 * @author littlespidy
 */
public class GWTRpcDeserializer {

    public static final String STRING_OBJECT = "java.lang.String";
    public static final String INTEGER_OBJECT = "java.lang.Integer";
    public static final String DOUBLE_OBJECT = "java.lang.Double";
    public static final String FLOAT_OBJECT = "java.lang.Float";
    public static final String BYTE_OBJECT = "java.lang.Byte";
    public static final String BOOLEAN_OBJECT = "java.lang.Boolean";
    public static final String SHORT_OBJECT = "java.lang.Short";
    public static final String CHAR_OBJECT = "java.lang.Char";
    public static final String LONG_OBJECT = "java.lang.Long";

    public static final String INT = "I";
    public static final String DOUBLE = "D";
    public static final String FLOAT = "F";
    public static final String BYTE = "B";
    public static final String BOOLEAN = "Z";
    public static final String SHORT = "S";
    public static final String CHAR = "C";
    public static final String LONG = "J";

    public static final int FLAG_ELIDE_TYPE_NAMES = 0x1;
    public static final int FLAG_RPC_TOKEN_INCLUDED = 0x2;

    private static final Set<String> PRIMITIVES = Set.of(INT, DOUBLE, FLOAT, BYTE, BOOLEAN, SHORT, CHAR, LONG);
    private static final Set<String> NUMERICS = Set.of(
            INT, CHAR, BOOLEAN, BYTE, SHORT, LONG,
            INTEGER_OBJECT, CHAR_OBJECT, BYTE_OBJECT, BOOLEAN_OBJECT, SHORT_OBJECT, LONG_OBJECT
    );

    /**
     * Deserializes a raw GWT-RPC payload string into a GWTRpcPayload object.
     */
    public static GWTRpcPayload deserialize(String rpcString) {
        GWTRpcPayload payload = new GWTRpcPayload();
        if (rpcString == null || rpcString.isBlank()) {
            return payload;
        }

        payload.setRawPayload(rpcString.trim());
        String[] tokens = rpcString.split("\\|", -1);
        if (tokens.length < 5) {
            return payload;
        }

        try {
            int streamVersion = Integer.parseInt(tokens[0].trim());
            int flags = Integer.parseInt(tokens[1].trim());
            int columns = Integer.parseInt(tokens[2].trim());

            payload.setStreamVersion(streamVersion);
            payload.setFlags(flags);
            payload.setStringTableLength(columns);

            // Extract string table (1-based, index 0 is empty)
            List<String> stringTable = new ArrayList<>();
            stringTable.add(""); // dummy 0th entry
            for (int i = 0; i < columns && (3 + i) < tokens.length; i++) {
                stringTable.add(tokens[3 + i]);
            }
            payload.setStringTable(stringTable);

            // Remaining tokens are index stream
            int indexStart = 3 + columns;
            List<Integer> indexList = new ArrayList<>();
            for (int i = indexStart; i < tokens.length; i++) {
                String t = tokens[i].trim();
                if (!t.isEmpty()) {
                    try {
                        indexList.add(Integer.parseInt(t));
                    } catch (NumberFormatException ignored) {}
                }
            }
            payload.setIndexTable(indexList);

            if (indexList.isEmpty()) {
                return payload;
            }

            int idxPtr = 0;

            // Read header properties (Base URL, Strong Name, Interface, Method)
            if ((flags & FLAG_RPC_TOKEN_INCLUDED) != 0) {
                if (idxPtr < indexList.size()) payload.setBaseUrl(getString(stringTable, indexList.get(idxPtr++)));
                if (idxPtr < indexList.size()) payload.setStrongName(getString(stringTable, indexList.get(idxPtr++)));
                if (idxPtr < indexList.size()) payload.setXsrfTokenName(getString(stringTable, indexList.get(idxPtr++)));
                if (idxPtr < indexList.size()) payload.setXsrfTokenValue(getString(stringTable, indexList.get(idxPtr++)));
                if (idxPtr < indexList.size()) payload.setServiceInterface(getString(stringTable, indexList.get(idxPtr++)));
                if (idxPtr < indexList.size()) payload.setMethodName(getString(stringTable, indexList.get(idxPtr++)));
            } else {
                if (idxPtr < indexList.size()) payload.setBaseUrl(getString(stringTable, indexList.get(idxPtr++)));
                if (idxPtr < indexList.size()) payload.setStrongName(getString(stringTable, indexList.get(idxPtr++)));
                if (idxPtr < indexList.size()) payload.setServiceInterface(getString(stringTable, indexList.get(idxPtr++)));
                if (idxPtr < indexList.size()) payload.setMethodName(getString(stringTable, indexList.get(idxPtr++)));
            }

            // Read parameter count
            if (idxPtr < indexList.size()) {
                int paramCount = indexList.get(idxPtr++);
                List<String> paramTypes = new ArrayList<>();

                for (int i = 0; i < paramCount && idxPtr < indexList.size(); i++) {
                    int typeIdx = indexList.get(idxPtr++);
                    String typeName = getString(stringTable, typeIdx);
                    paramTypes.add(typeName);
                }

                // Read values for each parameter
                for (String pType : paramTypes) {
                    GWTRpcParameter param = new GWTRpcParameter(pType);
                    String cleanType = param.getCleanTypename();

                    if (cleanType.equals(STRING_OBJECT)) {
                        param.setStringType(true);
                        if (idxPtr < indexList.size()) {
                            int valIdx = indexList.get(idxPtr++);
                            String val = getString(stringTable, valIdx);
                            param.addValue(val);
                            // Mark string position in tokens for fuzzing (valIdx + 2 in 0-based token array)
                            int tokenPos = 2 + valIdx;
                            param.addFuzzableIndex(tokenPos);
                            payload.markFuzzable(tokenPos, "%s");
                        }
                    } else if (cleanType.equals(LONG) || cleanType.equals(LONG_OBJECT)) {
                        param.setNumeric(true);
                        if (idxPtr < indexList.size()) {
                            int valIdx = indexList.get(idxPtr++);
                            String rawLong = (valIdx > 0 && valIdx < stringTable.size())
                                    ? stringTable.get(valIdx)
                                    : String.valueOf(valIdx);
                            long decodedVal = GwtLongCodec.decode(rawLong);
                            param.addValue(decodedVal + " (raw: " + rawLong + ")");
                            int tokenPos = (valIdx > 0 && valIdx < stringTable.size()) ? 2 + valIdx : (indexStart + idxPtr - 1);
                            param.addFuzzableIndex(tokenPos);
                            payload.markFuzzable(tokenPos, "%d");
                        }
                    } else if (NUMERICS.contains(cleanType) || PRIMITIVES.contains(cleanType)) {
                        param.setNumeric(true);
                        if (idxPtr < indexList.size()) {
                            int numVal = indexList.get(idxPtr++);
                            param.addValue(numVal);
                            int tokenPos = indexStart + idxPtr - 1;
                            param.addFuzzableIndex(tokenPos);
                            payload.markFuzzable(tokenPos, "%d");
                        }
                    } else if (cleanType.contains("List") || cleanType.startsWith("[")) {
                        param.setList(true);
                        if (idxPtr < indexList.size()) {
                            int subtypeIdx = indexList.get(idxPtr++);
                            String subtype = getString(stringTable, subtypeIdx);
                            int count = (idxPtr < indexList.size()) ? indexList.get(idxPtr++) : 0;
                            List<String> listVals = new ArrayList<>();
                            for (int k = 0; k < count && idxPtr < indexList.size(); k++) {
                                int elemTypeIdx = indexList.get(idxPtr++);
                                int elemValIdx = (idxPtr < indexList.size()) ? indexList.get(idxPtr++) : 0;
                                String elemVal = getString(stringTable, elemValIdx);
                                listVals.add(elemVal);
                                int tokenPos = 2 + elemValIdx;
                                param.addFuzzableIndex(tokenPos);
                                payload.markFuzzable(tokenPos, "%s");
                            }
                            param.addValue(listVals);
                        }
                    } else {
                        param.setCustomObject(true);
                        // Read member indices until end or next param
                        while (idxPtr < indexList.size()) {
                            int nextIdx = indexList.get(idxPtr++);
                            if (nextIdx > 0 && nextIdx < stringTable.size()) {
                                String memberVal = stringTable.get(nextIdx);
                                param.addValue(memberVal);
                                int tokenPos = 2 + nextIdx;
                                param.addFuzzableIndex(tokenPos);
                                payload.markFuzzable(tokenPos, "%s");
                            } else {
                                param.addValue(nextIdx);
                                int tokenPos = indexStart + idxPtr - 1;
                                param.addFuzzableIndex(tokenPos);
                                payload.markFuzzable(tokenPos, "%d");
                            }
                        }
                    }

                    payload.addParameter(param);
                }
            }

        } catch (Exception e) {
            // Graceful fallback on unexpected or truncated payloads
        }

        return payload;
    }

    private static String getString(List<String> table, int idx) {
        if (idx > 0 && idx < table.size()) {
            return table.get(idx);
        }
        return "idx_" + idx;
    }

    // ── Arming & Delimiting Methods ──────────────────────────────────────────

    /**
     * Surrounds all identified fuzzable values with Burp Intruder section symbols (§...§).
     */
    public static String armWithIntruderMarkers(String rpcString) {
        return surroundFuzzable(rpcString, "§", "§");
    }

    /**
     * Surrounds all identified fuzzable values with custom prefix and suffix strings.
     */
    public static String surroundFuzzable(String rpcString, String prefix, String suffix) {
        if (rpcString == null || rpcString.isBlank()) return rpcString;

        GWTRpcPayload payload = deserialize(rpcString);
        String[] tokens = rpcString.split("\\|", -1);
        boolean hasTrailing = rpcString.endsWith("|");

        for (Map.Entry<Integer, String> entry : payload.getFuzzableIndices().entrySet()) {
            int idx = entry.getKey();
            if (idx >= 0 && idx < tokens.length) {
                tokens[idx] = prefix + tokens[idx] + suffix;
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < tokens.length; i++) {
            sb.append(tokens[i]);
            if (i < tokens.length - 1 || hasTrailing) {
                sb.append("|");
            }
        }
        return sb.toString();
    }

    /**
     * Replaces all identified fuzzable values with a specified replacement string.
     */
    public static String replaceFuzzable(String rpcString, String replacement) {
        if (rpcString == null || rpcString.isBlank()) return rpcString;

        GWTRpcPayload payload = deserialize(rpcString);
        String[] tokens = rpcString.split("\\|", -1);
        boolean hasTrailing = rpcString.endsWith("|");

        for (Map.Entry<Integer, String> entry : payload.getFuzzableIndices().entrySet()) {
            int idx = entry.getKey();
            if (idx >= 0 && idx < tokens.length) {
                tokens[idx] = replacement;
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < tokens.length; i++) {
            sb.append(tokens[i]);
            if (i < tokens.length - 1 || hasTrailing) {
                sb.append("|");
            }
        }
        return sb.toString();
    }

    // ── AST Tree Formatting ──────────────────────────────────────────────────

    /**
     * Produces a clean, formatted ASCII text representation of the deserialized payload AST.
     */
    public static String formatAstTree(GWTRpcPayload payload) {
        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        sb.append("  Deserialized GWT-RPC Method Call\n");
        sb.append("================================================================================\n\n");
        sb.append("Stream Version      : ").append(payload.getStreamVersion()).append("\n");
        sb.append("Flags               : ").append(payload.getFlags());
        if (payload.hasXsrfToken()) {
            sb.append(" (FLAG_RPC_TOKEN_INCLUDED)");
        }
        sb.append("\n");
        sb.append("Columns in Table    : ").append(payload.getStringTableLength()).append("\n");
        sb.append("Base URL            : ").append(payload.getBaseUrl()).append("\n");
        sb.append("Strong Name (Hash)  : ").append(payload.getStrongName()).append("\n");

        if (payload.hasXsrfToken()) {
            sb.append("XSRF Token Name     : ").append(payload.getXsrfTokenName()).append("\n");
            sb.append("XSRF Token Value    : ").append(payload.getXsrfTokenValue()).append("\n");
        }

        sb.append("Service Interface   : ").append(payload.getServiceInterface()).append("\n");
        sb.append("Method Name         : ").append(payload.getMethodName()).append("\n");
        sb.append("Parameter Count     : ").append(payload.getParameters().size()).append("\n\n");

        sb.append("Parameters:\n");
        int pIndex = 1;
        for (GWTRpcParameter p : payload.getParameters()) {
            sb.append("  [").append(pIndex++).append("] Type : ").append(p.getTypename()).append("\n");
            sb.append("      Values: ").append(p.getValues()).append("\n");
            sb.append("      Fuzzable Token Offsets: ").append(p.getFuzzableIndices()).append("\n");
        }

        sb.append("\nString Table Entries (").append(payload.getStringTable().size()).append("):\n");
        for (int i = 1; i < payload.getStringTable().size(); i++) {
            sb.append("  [").append(i).append("] ").append(payload.getStringTable().get(i)).append("\n");
        }

        return sb.toString();
    }
}
