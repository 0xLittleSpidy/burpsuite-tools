// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.model;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe manager for tracking True Positive (TP) and False Positive (FP) classifications
 * on individual requests and entire secret types.
 *
 * Conflict Resolution & Precedence Rules:
 * Rule 1: Individual request classification overrides secret-type classification.
 * Rule 2: Secret-type classification applies to all requests except those with explicit individual classifications.
 * Order independence: Individual classifications take precedence over inherited secret-type classifications,
 * regardless of the order in which the classifications are applied.
 */
public class SecretClassificationManager {

    private final Map<Integer, SecretClassification> individualById = new ConcurrentHashMap<>();
    private final Map<String, SecretClassification> individualByKey = new ConcurrentHashMap<>();
    private final Map<String, SecretClassification> typeClassifications = new ConcurrentHashMap<>();

    /**
     * Mark an individual request/finding entry as TP, FP, or Not Verified.
     */
    public void markRequest(FindingEntry entry, SecretClassification classification) {
        if (entry == null) return;
        if (classification == null) {
            clearRequestClassification(entry);
            return;
        }
        individualById.put(entry.id(), classification);
        if (entry.dedupeKey() != null) {
            individualByKey.put(entry.dedupeKey(), classification);
        }
    }

    /**
     * Clear any explicit individual classification for a request finding, allowing it to inherit from secret type.
     */
    public void clearRequestClassification(FindingEntry entry) {
        if (entry == null) return;
        individualById.remove(entry.id());
        if (entry.dedupeKey() != null) {
            individualByKey.remove(entry.dedupeKey());
        }
    }

    /**
     * Mark an entire secret type as TP or FP.
     * This classification applies to all requests and responses associated with that secret type,
     * except those with explicit individual classifications.
     */
    public void markSecretType(String patternName, SecretClassification classification) {
        if (patternName == null || patternName.isBlank()) return;
        if (classification == null || classification == SecretClassification.NOT_VERIFIED) {
            typeClassifications.remove(patternName);
        } else {
            typeClassifications.put(patternName, classification);
        }
    }

    /**
     * Clear classification for a secret type.
     */
    public void clearSecretTypeClassification(String patternName) {
        if (patternName != null) {
            typeClassifications.remove(patternName);
        }
    }

    /**
     * Resolves the effective classification for a given finding according to precedence rules:
     * 1. Individual request classification overrides secret-type classification.
     * 2. Secret-type classification applies if no explicit individual classification exists.
     * 3. Defaults to NOT_VERIFIED.
     */
    public SecretClassification getEffectiveClassification(FindingEntry entry) {
        if (entry == null) {
            return SecretClassification.NOT_VERIFIED;
        }

        // 1. Check explicit individual classification first
        SecretClassification individual = individualById.get(entry.id());
        if (individual == null && entry.dedupeKey() != null) {
            individual = individualByKey.get(entry.dedupeKey());
        }
        if (individual != null) {
            return individual;
        }

        // 2. Check secret type classification
        if (entry.patternName() != null) {
            SecretClassification typeClass = typeClassifications.get(entry.patternName());
            if (typeClass != null) {
                return typeClass;
            }
        }

        // 3. Fallback
        return SecretClassification.NOT_VERIFIED;
    }

    public SecretClassification getIndividualClassification(FindingEntry entry) {
        if (entry == null) return null;
        SecretClassification res = individualById.get(entry.id());
        if (res == null && entry.dedupeKey() != null) {
            res = individualByKey.get(entry.dedupeKey());
        }
        return res;
    }

    public boolean hasIndividualClassification(FindingEntry entry) {
        return getIndividualClassification(entry) != null;
    }

    public SecretClassification getTypeClassification(String patternName) {
        if (patternName == null) return SecretClassification.NOT_VERIFIED;
        return typeClassifications.getOrDefault(patternName, SecretClassification.NOT_VERIFIED);
    }

    public void clear() {
        individualById.clear();
        individualByKey.clear();
        typeClassifications.clear();
    }
}
