// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.endpointinspector.service;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Token-level Jaccard similarity calculator ported from the reKover tool.
 * Evaluates whether path-parameter candidate siblings are served by the same handler
 * (tolerant of dynamic IDs, CSRF tokens, and timestamps).
 *
 * @author littlespidy
 */
public final class JaccardSimilarity_littlespidy {

    private static final Pattern ALPHANUMERIC_TOKEN = Pattern.compile("[a-zA-Z0-9]+");

    private JaccardSimilarity_littlespidy() {}

    /**
     * Computes integer percentage similarity (0 to 100) between two response body strings.
     */
    public static int calculate(String bodyA, String bodyB) {
        if (bodyA == null && bodyB == null) return 100;
        if (bodyA == null || bodyB == null) return 0;
        if (bodyA.equals(bodyB)) return 100;

        Set<String> tokensA = extractTokens(bodyA);
        Set<String> tokensB = extractTokens(bodyB);

        int na = tokensA.size();
        int nb = tokensB.size();
        if (na + nb == 0) return 0;

        int common = 0;
        Set<String> smaller = na <= nb ? tokensA : tokensB;
        Set<String> larger = na <= nb ? tokensB : tokensA;

        for (String t : smaller) {
            if (larger.contains(t)) {
                common++;
            }
        }

        return (200 * common) / (na + nb);
    }

    private static Set<String> extractTokens(String text) {
        Set<String> tokens = new HashSet<>();
        Matcher m = ALPHANUMERIC_TOKEN.matcher(text);
        while (m.find()) {
            tokens.add(m.group());
        }
        return tokens;
    }
}
