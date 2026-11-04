// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

import java.util.*;

/**
 * Reconstructed source project tree holding all extracted source files,
 * aggregated endpoints, secrets, comments, cloud URLs, dependencies, and GraphQL operations.
 *
 * @author littlespidy
 */
public class UnpackedProject {
    private final String sourceMapUrl;
    private final Map<String, UnpackedSourceFile> filesByPath = new LinkedHashMap<>();
    private final List<DiscoveredSecret> allSecrets = new ArrayList<>();
    private final List<DiscoveredEndpoint> allEndpoints = new ArrayList<>();
    private final List<DiscoveredComment> allComments = new ArrayList<>();
    private final List<DiscoveredCloudUrl> allCloudUrls = new ArrayList<>();
    private final List<DiscoveredDependency> allDependencies = new ArrayList<>();
    private final List<DiscoveredSecurityBypass> allSecurityBypasses = new ArrayList<>();
    private final List<DiscoveredGraphQLOperation> allGraphQLOperations = new ArrayList<>();
    private final List<DiscoveredInternalIpAndSsn_littlespidy> allInternalIpsAndSsns = new ArrayList<>();

    public UnpackedProject(String sourceMapUrl) {
        this.sourceMapUrl = sourceMapUrl;
    }

    public String getSourceMapUrl() {
        return sourceMapUrl;
    }

    public synchronized void addFile(UnpackedSourceFile file) {
        filesByPath.put(file.relativePath(), file);
        if (file.secrets() != null) {
            allSecrets.addAll(file.secrets());
        }
        if (file.endpoints() != null) {
            allEndpoints.addAll(file.endpoints());
        }
        if (file.comments() != null) {
            allComments.addAll(file.comments());
        }
        if (file.securityBypasses() != null) {
            allSecurityBypasses.addAll(file.securityBypasses());
        }
        if (file.cloudUrls() != null) {
            allCloudUrls.addAll(file.cloudUrls());
        }
        if (file.dependencies() != null) {
            allDependencies.addAll(file.dependencies());
        }
        if (file.graphQLOperations() != null) {
            allGraphQLOperations.addAll(file.graphQLOperations());
        }
        if (file.internalIpsAndSsns() != null) {
            allInternalIpsAndSsns.addAll(file.internalIpsAndSsns());
        }
    }

    public synchronized Map<String, UnpackedSourceFile> getFilesByPath() {
        return Collections.unmodifiableMap(filesByPath);
    }

    public synchronized Collection<UnpackedSourceFile> getFiles() {
        return Collections.unmodifiableCollection(filesByPath.values());
    }

    public synchronized UnpackedSourceFile getFile(String path) {
        return filesByPath.get(path);
    }

    public synchronized List<DiscoveredSecret> getAllSecrets() {
        return Collections.unmodifiableList(allSecrets);
    }

    public synchronized List<DiscoveredEndpoint> getAllEndpoints() {
        return Collections.unmodifiableList(allEndpoints);
    }

    public synchronized List<DiscoveredComment> getAllComments() {
        return Collections.unmodifiableList(allComments);
    }

    public synchronized List<DiscoveredSecurityBypass> getAllSecurityBypasses() {
        return Collections.unmodifiableList(allSecurityBypasses);
    }

    public synchronized List<DiscoveredCloudUrl> getAllCloudUrls() {
        return Collections.unmodifiableList(allCloudUrls);
    }

    public synchronized List<DiscoveredDependency> getAllDependencies() {
        return Collections.unmodifiableList(allDependencies);
    }

    public synchronized List<DiscoveredGraphQLOperation> getAllGraphQLOperations() {
        return Collections.unmodifiableList(allGraphQLOperations);
    }

    public synchronized List<DiscoveredInternalIpAndSsn_littlespidy> getAllInternalIpsAndSsns() {
        return Collections.unmodifiableList(allInternalIpsAndSsns);
    }

    public synchronized boolean updateInternalIpAndSsn(DiscoveredInternalIpAndSsn_littlespidy oldItem, DiscoveredInternalIpAndSsn_littlespidy newItem) {
        if (oldItem == null || newItem == null) return false;
        boolean updated = false;
        for (int i = 0; i < allInternalIpsAndSsns.size(); i++) {
            DiscoveredInternalIpAndSsn_littlespidy item = allInternalIpsAndSsns.get(i);
            if (item == oldItem || (Objects.equals(item.matchValue(), oldItem.matchValue())
                    && Objects.equals(item.sourceLocation(), oldItem.sourceLocation())
                    && item.line() == oldItem.line())) {
                allInternalIpsAndSsns.set(i, newItem);
                updated = true;
            }
        }
        return updated;
    }

    public synchronized void setAllFindings(
        List<DiscoveredSecret> secrets,
        List<DiscoveredEndpoint> endpoints,
        List<DiscoveredCloudUrl> cloudUrls,
        List<DiscoveredDependency> dependencies,
        List<DiscoveredComment> comments,
        List<DiscoveredSecurityBypass> securityBypasses,
        List<DiscoveredGraphQLOperation> graphQLOperations
    ) {
        if (secrets != null) { allSecrets.clear(); allSecrets.addAll(secrets); }
        if (endpoints != null) { allEndpoints.clear(); allEndpoints.addAll(endpoints); }
        if (cloudUrls != null) { allCloudUrls.clear(); allCloudUrls.addAll(cloudUrls); }
        if (dependencies != null) { allDependencies.clear(); allDependencies.addAll(dependencies); }
        if (comments != null) { allComments.clear(); allComments.addAll(comments); }
        if (securityBypasses != null) { allSecurityBypasses.clear(); allSecurityBypasses.addAll(securityBypasses); }
        if (graphQLOperations != null) { allGraphQLOperations.clear(); allGraphQLOperations.addAll(graphQLOperations); }
    }

    public synchronized boolean updateSecret(DiscoveredSecret oldSec, DiscoveredSecret newSec) {
        boolean updated = false;
        for (int i = 0; i < allSecrets.size(); i++) {
            DiscoveredSecret s = allSecrets.get(i);
            if (s == oldSec || (Objects.equals(s.secretValue(), oldSec.secretValue())
                    && Objects.equals(s.sourceLocation(), oldSec.sourceLocation())
                    && s.line() == oldSec.line())) {
                allSecrets.set(i, newSec);
                updated = true;
            }
        }
        return updated;
    }

    public synchronized boolean updateEndpoint(DiscoveredEndpoint oldEp, DiscoveredEndpoint newEp) {
        boolean updated = false;
        for (int i = 0; i < allEndpoints.size(); i++) {
            DiscoveredEndpoint e = allEndpoints.get(i);
            if (e == oldEp || (Objects.equals(e.endpoint(), oldEp.endpoint())
                    && Objects.equals(e.sourceLocation(), oldEp.sourceLocation())
                    && e.line() == oldEp.line())) {
                allEndpoints.set(i, newEp);
                updated = true;
            }
        }
        return updated;
    }

    public synchronized boolean updateComment(DiscoveredComment oldComm, DiscoveredComment newComm) {
        boolean updated = false;
        for (int i = 0; i < allComments.size(); i++) {
            DiscoveredComment c = allComments.get(i);
            if (c == oldComm || (Objects.equals(c.commentText(), oldComm.commentText())
                    && Objects.equals(c.sourceLocation(), oldComm.sourceLocation())
                    && c.line() == oldComm.line())) {
                allComments.set(i, newComm);
                updated = true;
            }
        }
        return updated;
    }

    public synchronized boolean updateSecurityBypass(DiscoveredSecurityBypass oldBypass, DiscoveredSecurityBypass newBypass) {
        boolean updated = false;
        for (int i = 0; i < allSecurityBypasses.size(); i++) {
            DiscoveredSecurityBypass b = allSecurityBypasses.get(i);
            if (b == oldBypass || (Objects.equals(b.method(), oldBypass.method())
                    && Objects.equals(b.sourceLocation(), oldBypass.sourceLocation())
                    && b.line() == oldBypass.line())) {
                allSecurityBypasses.set(i, newBypass);
                updated = true;
            }
        }
        return updated;
    }

    public synchronized boolean updateCloudUrl(DiscoveredCloudUrl oldCu, DiscoveredCloudUrl newCu) {
        boolean updated = false;
        for (int i = 0; i < allCloudUrls.size(); i++) {
            DiscoveredCloudUrl u = allCloudUrls.get(i);
            if (u == oldCu || (Objects.equals(u.cloudUrl(), oldCu.cloudUrl())
                    && Objects.equals(u.sourceLocation(), oldCu.sourceLocation())
                    && u.line() == oldCu.line())) {
                allCloudUrls.set(i, newCu);
                updated = true;
            }
        }
        return updated;
    }

    public synchronized boolean updateDependency(DiscoveredDependency oldDep, DiscoveredDependency newDep) {
        boolean updated = false;
        for (int i = 0; i < allDependencies.size(); i++) {
            DiscoveredDependency d = allDependencies.get(i);
            if (d == oldDep || (Objects.equals(d.packageName(), oldDep.packageName())
                    && Objects.equals(d.sourceLocation(), oldDep.sourceLocation())
                    && d.line() == oldDep.line())) {
                allDependencies.set(i, newDep);
                updated = true;
            }
        }
        return updated;
    }

    public synchronized int getTotalFiles() {
        return filesByPath.size();
    }

    public synchronized int getTotalLines() {
        int lines = 0;
        for (UnpackedSourceFile f : filesByPath.values()) {
            lines += f.lineCount();
        }
        return lines;
    }
}
