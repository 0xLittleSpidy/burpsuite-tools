// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.strategy;

import com.littlespidy.apiinspector.model.ProbeMutation_littlespidy;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strategy for discovering API versions embedded in subdomains / hostnames.
 */
public class SubdomainStrategy_littlespidy implements VersionStrategy_littlespidy {

    private static final Pattern PREFIX_HOST_VERSION = Pattern.compile("^(v\\d+)\\.(.+)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern INFIX_HOST_VERSION = Pattern.compile("^([a-zA-Z0-9]+)[_\\-](v\\d+)\\.(.+)$", Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() {
        return "Subdomain";
    }

    @Override
    public List<ProbeMutation_littlespidy> generateMutations(HttpRequest baselineRequest, List<String> candidateVersions) {
        List<ProbeMutation_littlespidy> mutations = new ArrayList<>();
        HttpService service = baselineRequest.httpService();
        if (service == null) {
            return mutations;
        }

        String host = service.host();
        if (host == null || host.isEmpty()) {
            return mutations;
        }

        Set<String> seenHosts = new HashSet<>();
        seenHosts.add(host.toLowerCase());

        Matcher prefixMatcher = PREFIX_HOST_VERSION.matcher(host);
        Matcher infixMatcher = INFIX_HOST_VERSION.matcher(host);

        for (String cand : candidateVersions) {
            String cleanCand = cand.trim();
            if (cleanCand.isEmpty()) continue;

            String versionStr = cleanCand.toLowerCase().startsWith("v") ? cleanCand : "v" + cleanCand;
            String newHost = null;

            if (prefixMatcher.matches()) {
                newHost = versionStr + "." + prefixMatcher.group(2);
            } else if (infixMatcher.matches()) {
                newHost = infixMatcher.group(1) + "-" + versionStr + "." + infixMatcher.group(3);
            }

            if (newHost != null && seenHosts.add(newHost.toLowerCase())) {
                HttpService newService = HttpService.httpService(newHost, service.port(), service.secure());
                HttpRequest mutated = baselineRequest.withService(newService).withHeader("Host", newHost);
                mutations.add(new ProbeMutation_littlespidy(
                        getName(),
                        "Host: " + newHost,
                        mutated
                ));
            }
        }

        return mutations;
    }
}
