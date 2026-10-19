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
 * Strategy for discovering API versions passed via Cookie headers.
 */
public class CookieStrategy_littlespidy implements VersionStrategy_littlespidy {

    private static final String[] TARGET_COOKIES = {
            "api_version",
            "apiVersion",
            "version"
    };

    @Override
    public String getName() {
        return "Cookie";
    }

    @Override
    public List<ProbeMutation_littlespidy> generateMutations(HttpRequest baselineRequest, List<String> candidateVersions) {
        List<ProbeMutation_littlespidy> mutations = new ArrayList<>();
        String existingCookie = baselineRequest.headerValue("Cookie");
        Set<String> seenCookies = new HashSet<>();
        if (existingCookie != null) {
            seenCookies.add(existingCookie);
        }

        for (String cookieName : TARGET_COOKIES) {
            Pattern cookiePattern = Pattern.compile("(^|;\\s*)" + Pattern.quote(cookieName) + "=([^;]*)", Pattern.CASE_INSENSITIVE);

            for (String cand : candidateVersions) {
                String cleanCand = cand.trim();
                if (cleanCand.isEmpty()) continue;

                String newCookie;
                if (existingCookie != null && !existingCookie.isEmpty()) {
                    Matcher m = cookiePattern.matcher(existingCookie);
                    if (m.find()) {
                        String existingVal = m.group(2);
                        if (existingVal.equalsIgnoreCase(cleanCand)) {
                            continue;
                        }
                        newCookie = m.replaceFirst("$1" + cookieName + "=" + cleanCand);
                    } else {
                        newCookie = existingCookie + "; " + cookieName + "=" + cleanCand;
                    }
                } else {
                    newCookie = cookieName + "=" + cleanCand;
                }

                if (seenCookies.add(newCookie)) {
                    HttpRequest mutated = baselineRequest.withHeader("Cookie", newCookie);
                    mutations.add(new ProbeMutation_littlespidy(
                            getName(),
                            "Cookie: " + cookieName + "=" + cleanCand,
                            mutated
                    ));
                }
            }
        }

        return mutations;
    }
}
