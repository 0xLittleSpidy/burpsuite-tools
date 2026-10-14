// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.parser;

import java.util.regex.Pattern;

/**
 * Classifies GWT source code into bootstrap, permutation, or fragment variants.
 *
 * @author littlespidy
 */
public class GWTClassifier {

    public enum CodeType {
        BOOTSTRAP_OBFUSCATED,
        BOOTSTRAP_CLEAN,
        PERMUTATION_OBFUSCATED,
        PERMUTATION_CLEAN,
        FRAGMENT_OBFUSCATED,
        FRAGMENT_CLEAN,
        UNKNOWN
    }

    private static final String R_VAR = "[a-zA-Z0-9_.\\$]+";

    private static final Pattern BOOTSTRAP_PATTERN_O = Pattern.compile("^function .*?\\(\\)\\{.*?=\\s*\"?'?bootstrap.*?=\\s*\"?'?begin", Pattern.DOTALL);
    private static final Pattern BOOTSTRAP_PATTERN_C = Pattern.compile("^function " + R_VAR + "\\(\\)\\{");

    private static final Pattern PERMUTATION_PATTERN_O = Pattern.compile("^" + R_VAR + "\\.onScriptDownloaded\\(\\[.*", Pattern.DOTALL);
    private static final Pattern PERMUTATION_PATTERN_C = Pattern.compile("^var \\$wnd = \\$wnd \\|\\| window\\.parent;");

    private static final Pattern FRAG_PATTERN_O = Pattern.compile("^" + R_VAR + "\\.runAsyncCallback.*", Pattern.DOTALL);
    private static final Pattern FRAG_PATTERN_C = Pattern.compile("^" + R_VAR + "\\.runAsyncCallback[0-9]+\\(['\"](?:(?:\\$entry)|(?:defineClass))\\(");

    public static CodeType classify(String code) {
        if (code == null || code.isBlank()) {
            return CodeType.UNKNOWN;
        }

        String sample = code.length() > 2000 ? code.substring(0, 2000) : code;

        if (BOOTSTRAP_PATTERN_O.matcher(sample).find()) {
            return CodeType.BOOTSTRAP_OBFUSCATED;
        }
        if (BOOTSTRAP_PATTERN_C.matcher(sample).find()) {
            return CodeType.BOOTSTRAP_CLEAN;
        }
        if (PERMUTATION_PATTERN_O.matcher(sample).find()) {
            return CodeType.PERMUTATION_OBFUSCATED;
        }
        if (PERMUTATION_PATTERN_C.matcher(sample).find()) {
            return CodeType.PERMUTATION_CLEAN;
        }
        if (FRAG_PATTERN_C.matcher(sample).find()) {
            return CodeType.FRAGMENT_CLEAN;
        }
        if (FRAG_PATTERN_O.matcher(sample).find()) {
            return CodeType.FRAGMENT_OBFUSCATED;
        }

        if (sample.contains(".onScriptDownloaded([")) {
            return CodeType.PERMUTATION_OBFUSCATED;
        }
        if (sample.contains("unflattenKeylistIntoAnswers") || sample.contains("selectingPermutation")) {
            return CodeType.BOOTSTRAP_OBFUSCATED;
        }
        if (sample.contains(".cache.html") || sample.contains(".cache.js")) {
            return CodeType.PERMUTATION_OBFUSCATED;
        }

        return CodeType.UNKNOWN;
    }
}
