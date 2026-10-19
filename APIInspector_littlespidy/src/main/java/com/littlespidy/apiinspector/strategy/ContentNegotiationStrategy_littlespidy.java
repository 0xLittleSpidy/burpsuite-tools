// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.strategy;

import com.littlespidy.apiinspector.model.ProbeMutation_littlespidy;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strategy for discovering API versions via Content Negotiation (Accept and Content-Type media types).
 */
public class ContentNegotiationStrategy_littlespidy implements VersionStrategy_littlespidy {

    private static final Pattern VENDOR_MIME_PATTERN = Pattern.compile(
            "application/vnd\\.([a-zA-Z0-9_\\-\\.]+)\\.v?([0-9a-zA-Z_\\-\\.]+)\\+([a-zA-Z0-9_\\-\\.]+)",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    public String getName() {
        return "Content Negotiation";
    }

    @Override
    public List<ProbeMutation_littlespidy> generateMutations(HttpRequest baselineRequest, List<String> candidateVersions) {
        List<ProbeMutation_littlespidy> mutations = new ArrayList<>();
        Set<String> seenHeaders = new HashSet<>();

        String existingAccept = baselineRequest.headerValue("Accept");
        String existingContentType = baselineRequest.headerValue("Content-Type");

        // 1. Check if existing Accept has a vendor pattern
        boolean hasVendorAccept = existingAccept != null && VENDOR_MIME_PATTERN.matcher(existingAccept).find();

        for (String cand : candidateVersions) {
            String cleanCand = cand.trim();
            if (cleanCand.isEmpty()) continue;

            String numericCand = cleanCand.startsWith("v") || cleanCand.startsWith("V") ? cleanCand.substring(1) : cleanCand;

            // Pattern 1: Accept: application/json; version={version}
            String accept1 = "application/json; version=" + cleanCand;
            if (shouldAddHeader("Accept", accept1, existingAccept, seenHeaders)) {
                mutations.add(new ProbeMutation_littlespidy(
                        getName(),
                        "Accept: " + accept1,
                        baselineRequest.withHeader("Accept", accept1)
                ));
            }

            // Pattern 2: Accept: application/json; v={version}
            String accept2 = "application/json; v=" + numericCand;
            if (shouldAddHeader("Accept", accept2, existingAccept, seenHeaders)) {
                mutations.add(new ProbeMutation_littlespidy(
                        getName(),
                        "Accept: " + accept2,
                        baselineRequest.withHeader("Accept", accept2)
                ));
            }

            // Pattern 3: If baseline had vendor MIME, replace version
            if (hasVendorAccept) {
                Matcher m = VENDOR_MIME_PATTERN.matcher(existingAccept);
                if (m.find()) {
                    String vendor = m.group(1);
                    String subtype = m.group(3);
                    String vendorAccept = "application/vnd." + vendor + ".v" + numericCand + "+" + subtype;
                    if (shouldAddHeader("Accept", vendorAccept, existingAccept, seenHeaders)) {
                        mutations.add(new ProbeMutation_littlespidy(
                                getName(),
                                "Accept: " + vendorAccept,
                                baselineRequest.withHeader("Accept", vendorAccept)
                        ));
                    }
                }
            } else {
                // Pattern 4: Generic vendor MIME probe
                String genericVendor = "application/vnd.api.v" + numericCand + "+json";
                if (shouldAddHeader("Accept", genericVendor, existingAccept, seenHeaders)) {
                    mutations.add(new ProbeMutation_littlespidy(
                            getName(),
                            "Accept: " + genericVendor,
                            baselineRequest.withHeader("Accept", genericVendor)
                    ));
                }
            }

            // 5. If request has a body (e.g. POST, PUT, PATCH), probe Content-Type versioning
            String method = baselineRequest.method();
            if (method != null && ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method))) {
                String ct1 = "application/json; version=" + cleanCand;
                if (shouldAddHeader("Content-Type", ct1, existingContentType, seenHeaders)) {
                    mutations.add(new ProbeMutation_littlespidy(
                            getName(),
                            "Content-Type: " + ct1,
                            baselineRequest.withHeader("Content-Type", ct1)
                    ));
                }
            }
        }

        return mutations;
    }

    private boolean shouldAddHeader(String headerName, String value, String existingValue, Set<String> seen) {
        if (existingValue != null && existingValue.equalsIgnoreCase(value)) {
            return false;
        }
        return seen.add(headerName + ":" + value);
    }
}
