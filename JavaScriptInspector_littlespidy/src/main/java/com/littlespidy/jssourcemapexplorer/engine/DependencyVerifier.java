// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.jssourcemapexplorer.model.DiscoveredDependency;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Asynchronously verifies package dependencies against public npm registry
 * (registry.npmjs.org and npmjs.com/org/) to detect potential Dependency Confusion vulnerabilities.
 *
 * @author littlespidy
 */
public class DependencyVerifier {

    private final MontoyaApi api;
    private final ExecutorService executor = Executors.newFixedThreadPool(4, r -> {
        Thread t = new Thread(r, "DependencyConfusionVerifier");
        t.setDaemon(true);
        return t;
    });

    public DependencyVerifier(MontoyaApi api) {
        this.api = api;
    }

    public void verifyAll(List<DiscoveredDependency> dependencies, Runnable onComplete) {
        if (dependencies == null || dependencies.isEmpty()) {
            if (onComplete != null) onComplete.run();
            return;
        }

        executor.submit(() -> {
            for (DiscoveredDependency dep : dependencies) {
                if ("Registered (OK)".equals(dep.status()) || dep.status().startsWith("VULNERABLE")) {
                    continue; // already verified
                }
                verifySingle(dep);
            }
            if (onComplete != null) {
                onComplete.run();
            }
        });
    }

    public void verifySingle(DiscoveredDependency dep) {
        String pkg = dep.packageName();
        if (pkg == null || pkg.trim().isEmpty() || pkg.equals("-")) {
            dep.setStatus("Invalid Name", "Empty or missing package name");
            return;
        }

        dep.setStatus("Checking...", "Querying npm registry...");

        try {
            if (pkg.startsWith("@")) {
                // Scoped package e.g. @org/pkg
                int slashIdx = pkg.indexOf('/');
                String org = (slashIdx > 1) ? pkg.substring(1, slashIdx) : pkg.substring(1);

                String orgUrl = "https://www.npmjs.com/org/" + org;
                HttpRequest req = HttpRequest.httpRequestFromUrl(orgUrl);
                HttpResponse resp = (api != null && api.http() != null)
                    ? api.http().sendRequest(req).response()
                    : null;

                if (resp != null) {
                    int code = resp.statusCode();
                    if (code == 404) {
                        dep.setStatus(
                            "VULNERABLE: Org Not Found (404)",
                            "Organization @" + org + " is not registered on npmjs.com! Vulnerable to scoped dependency pre-registration."
                        );
                    } else if (code == 200) {
                        dep.setStatus("Registered Org (OK)", "Organization @" + org + " exists on npmjs.com");
                    } else {
                        dep.setStatus("HTTP " + code, "npm returned status code " + code);
                    }
                } else {
                    dep.setStatus("Connection Failed", "Unable to query npmjs.com");
                }
            } else {
                // Public package
                String registryUrl = "https://registry.npmjs.org/" + pkg;
                HttpRequest req = HttpRequest.httpRequestFromUrl(registryUrl);
                HttpResponse resp = (api != null && api.http() != null)
                    ? api.http().sendRequest(req).response()
                    : null;

                if (resp != null) {
                    int code = resp.statusCode();
                    if (code == 404) {
                        dep.setStatus(
                            "VULNERABLE: 404 Unclaimed",
                            "Package '" + pkg + "' does not exist on registry.npmjs.org! Attackers can claim it for dependency confusion."
                        );
                    } else if (code == 200) {
                        dep.setStatus("Registered (OK)", "Package exists on public npm registry");
                    } else {
                        dep.setStatus("HTTP " + code, "npm registry returned status code " + code);
                    }
                } else {
                    dep.setStatus("Connection Failed", "Unable to query registry.npmjs.org");
                }
            }
        } catch (Exception e) {
            dep.setStatus("Check Error", e.getMessage() != null ? e.getMessage() : e.toString());
        }
    }
}
