// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.model;

import java.util.*;

/**
 * Computes and holds the cross-token comparison rows across N tokens.
 */
public class ComparisonResult {

    private static final Set<String> TIMESTAMP_CLAIMS = Set.of("exp", "iat", "nbf", "auth_time", "updated_at");

    private final List<ComparisonRow> allRows;
    private final int identicalCount;
    private final int mismatchCount;
    private final int partialCount;

    public ComparisonResult(List<ComparisonRow> allRows) {
        this.allRows = Collections.unmodifiableList(allRows);

        int identical = 0;
        int mismatch = 0;
        int partial = 0;

        for (ComparisonRow row : allRows) {
            if (row.getDiffType() == DiffType.IDENTICAL) {
                identical++;
            } else if (row.getDiffType() == DiffType.MISMATCH) {
                mismatch++;
            } else if (row.getDiffType() == DiffType.PARTIAL_ABSENT) {
                partial++;
            }
        }

        this.identicalCount = identical;
        this.mismatchCount = mismatch;
        this.partialCount = partial;
    }

    public static ComparisonResult compute(List<JWTTokenModel> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return new ComparisonResult(Collections.emptyList());
        }

        List<ComparisonRow> rows = new ArrayList<>();

        // 1. Gather all Header keys preserving appearance order
        LinkedHashSet<String> headerKeys = new LinkedHashSet<>();
        for (JWTTokenModel t : tokens) {
            if (t.isValid()) {
                headerKeys.addAll(t.getHeaderClaims().keySet());
            }
        }

        for (String key : headerKeys) {
            rows.add(buildRow("Header", key, tokens, false));
        }

        // 2. Gather all Payload keys preserving appearance order
        LinkedHashSet<String> payloadKeys = new LinkedHashSet<>();
        for (JWTTokenModel t : tokens) {
            if (t.isValid()) {
                payloadKeys.addAll(t.getPayloadClaims().keySet());
            }
        }

        for (String key : payloadKeys) {
            boolean isTs = TIMESTAMP_CLAIMS.contains(key.toLowerCase());
            rows.add(buildRow("Payload", key, tokens, isTs));
        }

        return new ComparisonResult(rows);
    }

    private static ComparisonRow buildRow(String section, String key, List<JWTTokenModel> tokens, boolean isTimestamp) {
        Map<Integer, Object> rawValues = new LinkedHashMap<>();
        Map<Integer, String> formattedValues = new LinkedHashMap<>();

        int presentCount = 0;
        int validTokensCount = 0;
        Object firstValue = null;
        boolean allEqual = true;

        for (JWTTokenModel token : tokens) {
            if (!token.isValid()) {
                continue;
            }
            validTokensCount++;
            int slot = token.getSlotIndex();

            if (token.hasClaim(section, key)) {
                presentCount++;
                Object raw = token.getClaim(section, key);
                rawValues.put(slot, raw);

                String formatted;
                if (isTimestamp) {
                    formatted = token.getTimestampHumanReadable(key);
                } else {
                    formatted = JWTParser.formatClaimValue(raw);
                }
                formattedValues.put(slot, formatted);

                if (firstValue == null && presentCount == 1) {
                    firstValue = raw;
                } else {
                    if (!Objects.equals(String.valueOf(firstValue), String.valueOf(raw))) {
                        allEqual = false;
                    }
                }
            } else {
                formattedValues.put(slot, "[MISSING]");
            }
        }

        DiffType diffType;
        if (validTokensCount > 0 && presentCount < validTokensCount) {
            diffType = DiffType.PARTIAL_ABSENT;
        } else if (!allEqual) {
            diffType = DiffType.MISMATCH;
        } else {
            diffType = DiffType.IDENTICAL;
        }

        return new ComparisonRow(section, key, rawValues, formattedValues, diffType, isTimestamp);
    }

    public List<ComparisonRow> getAllRows() {
        return allRows;
    }

    public int getIdenticalCount() {
        return identicalCount;
    }

    public int getMismatchCount() {
        return mismatchCount;
    }

    public int getPartialCount() {
        return partialCount;
    }

    public int getTotalCount() {
        return allRows.size();
    }

    public int getDifferencesCount() {
        return mismatchCount + partialCount;
    }

    /**
     * Filters rows based on section, diff filter mode, and search text.
     */
    public List<ComparisonRow> filter(String sectionFilter, String diffFilter, String search) {
        return filter(sectionFilter, diffFilter, search, Collections.emptySet());
    }

    /**
     * Filters rows based on section, diff filter mode, search text, and ignored claim keys.
     * When diffFilter is "Differences Only", any row matching an ignored claim key will be excluded.
     */
    public List<ComparisonRow> filter(String sectionFilter, String diffFilter, String search, Set<String> ignoredClaimKeys) {
        List<ComparisonRow> filtered = new ArrayList<>();
        Set<String> normalizedIgnored = new HashSet<>();
        if (ignoredClaimKeys != null) {
            for (String k : ignoredClaimKeys) {
                if (k != null && !k.trim().isEmpty()) {
                    normalizedIgnored.add(k.trim().toLowerCase());
                }
            }
        }

        for (ComparisonRow row : allRows) {
            // 1. Section filter
            if (!"All".equalsIgnoreCase(sectionFilter) && !row.getSection().equalsIgnoreCase(sectionFilter)) {
                continue;
            }

            // 2. Diff filter
            if ("Differences Only".equalsIgnoreCase(diffFilter)) {
                if (row.getDiffType() == DiffType.IDENTICAL) {
                    continue;
                }
                if (normalizedIgnored.contains(row.getClaimKey().toLowerCase())) {
                    continue;
                }
            } else if ("Missing Only".equalsIgnoreCase(diffFilter)) {
                if (row.getDiffType() != DiffType.PARTIAL_ABSENT) {
                    continue;
                }
            } else if ("Matches Only".equalsIgnoreCase(diffFilter)) {
                if (row.getDiffType() != DiffType.IDENTICAL) {
                    continue;
                }
            }

            // 3. Search query
            if (!row.matchesSearch(search)) {
                continue;
            }

            filtered.add(row);
        }
        return filtered;
    }

    /**
     * Counts how many non-identical claims are currently ignored.
     */
    public int countIgnoredDifferences(Set<String> ignoredClaimKeys) {
        if (ignoredClaimKeys == null || ignoredClaimKeys.isEmpty()) {
            return 0;
        }
        Set<String> normalized = new HashSet<>();
        for (String k : ignoredClaimKeys) {
            if (k != null && !k.trim().isEmpty()) {
                normalized.add(k.trim().toLowerCase());
            }
        }
        int count = 0;
        for (ComparisonRow row : allRows) {
            if (row.getDiffType() != DiffType.IDENTICAL && normalized.contains(row.getClaimKey().toLowerCase())) {
                count++;
            }
        }
        return count;
    }
}
