// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.parser;

import java.math.BigInteger;

/**
 * Encodes and decodes GWT 64-bit long integers from/to GWT Base64 wire format.
 * In GWT-RPC payloads, 64-bit integers are encoded as Base64 strings using
 * [A-Za-z0-9] plus '$' and '_' (or '+' and '/').
 *
 * @author littlespidy
 */
public class GwtLongCodec {

    // GWT custom Base64 alphabet (64 chars)
    private static final String GWT_BASE64_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$_";

    // Standard RFC 4648 Base64 alphabet (64 chars)
    private static final String RFC4648_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * Decodes a GWT base64-encoded string into a 64-bit long value.
     */
    public static long decode(String code) {
        if (code == null || code.isBlank()) {
            return 0L;
        }

        code = code.trim();
        boolean negative = false;
        if (code.startsWith("-")) {
            negative = true;
            code = code.substring(1);
        }

        BigInteger result = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(64);

        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            int val = charToValue(c);
            if (val < 0) {
                // If invalid char, fallback to standard parsing if numeric
                try {
                    return Long.parseLong(code);
                } catch (NumberFormatException e) {
                    return 0L;
                }
            }
            result = result.multiply(base).add(BigInteger.valueOf(val));
        }

        long longVal = result.longValue();
        return negative ? -longVal : longVal;
    }

    /**
     * Encodes a 64-bit long value into GWT Base64 wire string format.
     */
    public static String encode(long number) {
        if (number == 0) {
            return "A";
        }

        boolean negative = false;
        if (number < 0) {
            negative = true;
            number = -number;
        }

        StringBuilder sb = new StringBuilder();
        while (number > 0) {
            int rem = (int) (number % 64);
            sb.append(GWT_BASE64_ALPHABET.charAt(rem));
            number = number / 64;
        }

        String encoded = sb.reverse().toString();
        return negative ? "-" + encoded : encoded;
    }

    private static int charToValue(char c) {
        int idx = GWT_BASE64_ALPHABET.indexOf(c);
        if (idx >= 0) return idx;

        idx = RFC4648_ALPHABET.indexOf(c);
        return idx;
    }
}
