// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents a discovered JavaScript script candidate along with its
 * origin classification, passive & active source map statuses, unpacked project data,
 * both JS and Source Map raw requests & responses, and discovered secrets/endpoints.
 *
 * @author littlespidy
 */
public class JsFileEntry {
    private final int id;
    private final String url;
    private final String host;
    private final String path;
    private final int statusCode;
    private final int contentLength;
    private final boolean firstParty;
    private final String originLabel;

    private volatile PassiveMapStatus passiveMapStatus;
    private volatile ActiveProbeStatus activeProbeStatus;
    private volatile boolean unpacked;
    private volatile String sourceMapLocation;
    private volatile UnpackedProject unpackedProject;

    // Discovered Secrets, Endpoints, Cloud URLs, and Dependencies from the JS file itself
    private final List<DiscoveredSecret> jsSecrets = new ArrayList<>();
    private final List<DiscoveredEndpoint> jsEndpoints = new ArrayList<>();
    private final List<DiscoveredCloudUrl> jsCloudUrls = new ArrayList<>();
    private final List<DiscoveredDependency> jsDependencies = new ArrayList<>();

    // Raw HTTP messages
    private final HttpRequest request;
    private final HttpResponse response;
    private volatile HttpRequest sourceMapRequest;
    private volatile HttpResponse sourceMapResponse;
    private final ZonedDateTime timestamp;

    public JsFileEntry(
        int id,
        String url,
        String host,
        String path,
        int statusCode,
        int contentLength,
        boolean firstParty,
        String originLabel,
        PassiveMapStatus passiveMapStatus,
        String sourceMapLocation,
        HttpRequest request,
        HttpResponse response,
        ZonedDateTime timestamp
    ) {
        this.id = id;
        this.url = url;
        this.host = host;
        this.path = path;
        this.statusCode = statusCode;
        this.contentLength = contentLength;
        this.firstParty = firstParty;
        this.originLabel = originLabel;
        this.passiveMapStatus = passiveMapStatus != null ? passiveMapStatus : PassiveMapStatus.NOT_FOUND;
        this.activeProbeStatus = ActiveProbeStatus.NOT_RUN;
        this.unpacked = false;
        this.sourceMapLocation = sourceMapLocation;
        this.request = request;
        this.response = response;
        this.timestamp = timestamp;
    }

    public int getId() { return id; }
    public String getUrl() { return url; }
    public String getHost() { return host; }
    public String getPath() { return path; }
    public int getStatusCode() { return statusCode; }
    public int getContentLength() { return contentLength; }
    public boolean isFirstParty() { return firstParty; }
    public String getOriginLabel() { return originLabel; }

    public PassiveMapStatus getPassiveMapStatus() { return passiveMapStatus; }
    public void setPassiveMapStatus(PassiveMapStatus status) { this.passiveMapStatus = status; }

    public ActiveProbeStatus getActiveProbeStatus() { return activeProbeStatus; }
    public void setActiveProbeStatus(ActiveProbeStatus status) { this.activeProbeStatus = status; }

    public boolean isUnpacked() { return unpacked; }
    public void setUnpacked(boolean unpacked) { this.unpacked = unpacked; }

    public String getSourceMapLocation() { return sourceMapLocation; }
    public void setSourceMapLocation(String location) { this.sourceMapLocation = location; }

    public boolean isMapExposed() {
        return (passiveMapStatus != null && passiveMapStatus.isFound())
            || (activeProbeStatus != null && activeProbeStatus.isPass())
            || unpacked;
    }

    public UnpackedProject getUnpackedProject() { return unpackedProject; }
    public synchronized void setUnpackedProject(UnpackedProject project) {
        this.unpackedProject = project;
        if (project != null) {
            this.unpacked = true;
        }
    }

    public synchronized void setJsReconFindings(
        List<DiscoveredSecret> secrets,
        List<DiscoveredEndpoint> endpoints,
        List<DiscoveredCloudUrl> cloudUrls,
        List<DiscoveredDependency> dependencies
    ) {
        jsSecrets.clear();
        if (secrets != null) jsSecrets.addAll(secrets);
        jsEndpoints.clear();
        if (endpoints != null) jsEndpoints.addAll(endpoints);
        jsCloudUrls.clear();
        if (cloudUrls != null) jsCloudUrls.addAll(cloudUrls);
        jsDependencies.clear();
        if (dependencies != null) jsDependencies.addAll(dependencies);
    }

    public synchronized void setJsReconFindings(List<DiscoveredSecret> secrets, List<DiscoveredEndpoint> endpoints) {
        setJsReconFindings(secrets, endpoints, Collections.emptyList(), Collections.emptyList());
    }

    public synchronized List<DiscoveredSecret> getJsSecrets() {
        return Collections.unmodifiableList(jsSecrets);
    }

    public synchronized List<DiscoveredEndpoint> getJsEndpoints() {
        return Collections.unmodifiableList(jsEndpoints);
    }

    public synchronized List<DiscoveredCloudUrl> getJsCloudUrls() {
        return Collections.unmodifiableList(jsCloudUrls);
    }

    public synchronized List<DiscoveredDependency> getJsDependencies() {
        return Collections.unmodifiableList(jsDependencies);
    }

    public synchronized String getJsReconSummary() {
        int epCount = jsEndpoints.size();
        int secCount = jsSecrets.size();
        int cloudCount = jsCloudUrls.size();
        int depCount = jsDependencies.size();
        return String.format("%d eps | %d sec | %d cloud | %d dep", epCount, secCount, cloudCount, depCount);
    }

    public synchronized String getMapReconSummary() {
        if (unpackedProject == null) return "-";
        int epCount = unpackedProject.getAllEndpoints().size();
        int secCount = unpackedProject.getAllSecrets().size();
        int cloudCount = unpackedProject.getAllCloudUrls().size();
        int depCount = unpackedProject.getAllDependencies().size();
        return String.format("%d eps | %d sec | %d cloud | %d dep", epCount, secCount, cloudCount, depCount);
    }

    public HttpRequest getRequest() { return request; }
    public HttpResponse getResponse() { return response; }

    public HttpRequest getSourceMapRequest() { return sourceMapRequest; }
    public void setSourceMapRequest(HttpRequest sourceMapRequest) { this.sourceMapRequest = sourceMapRequest; }

    public HttpResponse getSourceMapResponse() { return sourceMapResponse; }
    public void setSourceMapResponse(HttpResponse sourceMapResponse) { this.sourceMapResponse = sourceMapResponse; }

    public ZonedDateTime getTimestamp() { return timestamp; }
}
