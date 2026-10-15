// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents an enumerated GWT RPC method, its full parameter signature,
 * serialized GWT-RPC wire request payload, and probe test execution results.
 *
 * @author littlespidy
 */
public class GWTMethod {

    private final int id;
    private final String methodName;
    private final String serviceProxy;
    private final String rmtSvcIntName;
    private final String paramCount;
    private final List<String> methodSignature;
    private GWTService service;
    private String methodRpcCall = "";
    private String rawRpcCall = "";
    private final List<String> complexTypes = new ArrayList<>();
    private String fullEndpointUrl = "";

    // Probe results
    private boolean probed = false;
    private int probeStatusCode = -1;
    private int probeResponseLength = 0;
    private String probeResponseBody = "";
    private long probeResponseTimeMs = 0;
    private HttpRequest probeRequest;
    private HttpResponse probeResponse;
    private String probeNotes = "";

    public GWTMethod(int id, String methodName, String serviceProxy, String rmtSvcIntName,
                     String paramCount, List<String> methodSignature) {
        this.id = id;
        this.methodName = methodName != null ? methodName : "";
        this.serviceProxy = serviceProxy != null ? serviceProxy : "";
        this.rmtSvcIntName = rmtSvcIntName != null ? rmtSvcIntName : "";
        this.paramCount = paramCount != null ? paramCount : "0";
        this.methodSignature = methodSignature != null ? new ArrayList<>(methodSignature) : new ArrayList<>();
    }

    public int getId() {
        return id;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getServiceProxy() {
        return serviceProxy;
    }

    public String getServiceCategory() {
        if (serviceProxy.endsWith("_Proxy")) {
            return serviceProxy.substring(0, serviceProxy.length() - 6);
        }
        return serviceProxy;
    }

    public String getRmtSvcIntName() {
        return rmtSvcIntName;
    }

    public String getParamCount() {
        return paramCount;
    }

    public List<String> getMethodSignature() {
        return Collections.unmodifiableList(methodSignature);
    }

    public String getSignatureFormatted() {
        return methodName + "(" + String.join(", ", methodSignature) + ")";
    }

    public GWTService getService() {
        return service;
    }

    public void setService(GWTService service) {
        this.service = service;
    }

    public String getMethodRpcCall() {
        return methodRpcCall;
    }

    public void setMethodRpcCall(String methodRpcCall) {
        this.methodRpcCall = methodRpcCall != null ? methodRpcCall : "";
        this.rawRpcCall = this.methodRpcCall.replace("§", "");
    }

    public String getRawRpcCall() {
        return rawRpcCall;
    }

    public List<String> getComplexTypes() {
        return Collections.unmodifiableList(complexTypes);
    }

    public void setComplexTypes(List<String> complexTypes) {
        this.complexTypes.clear();
        if (complexTypes != null) {
            this.complexTypes.addAll(complexTypes);
        }
    }

    public String getFullEndpointUrl() {
        return fullEndpointUrl;
    }

    public void setFullEndpointUrl(String fullEndpointUrl) {
        this.fullEndpointUrl = fullEndpointUrl;
    }

    // ── Probe Accessors ──────────────────────────────────────────────────────

    public boolean isProbed() {
        return probed;
    }

    public int getProbeStatusCode() {
        return probeStatusCode;
    }

    public int getProbeResponseLength() {
        return probeResponseLength;
    }

    public String getProbeResponseBody() {
        return probeResponseBody;
    }

    public long getProbeResponseTimeMs() {
        return probeResponseTimeMs;
    }

    public HttpRequest getProbeRequest() {
        return probeRequest;
    }

    public HttpResponse getProbeResponse() {
        return probeResponse;
    }

    public String getProbeNotes() {
        return probeNotes;
    }

    public void setProbeResult(HttpRequest request, HttpResponse response, long elapsedMs) {
        this.probed = true;
        this.probeRequest = request;
        this.probeResponse = response;
        this.probeResponseTimeMs = elapsedMs;
        if (response != null) {
            this.probeStatusCode = response.statusCode();
            this.probeResponseLength = response.body().length();
            this.probeResponseBody = response.bodyToString();
            this.probeNotes = "HTTP " + probeStatusCode + " (" + elapsedMs + "ms)";
        } else {
            this.probeStatusCode = 0;
            this.probeNotes = "Probe Connection Failed";
        }
    }

    public void restoreProbeResult(HttpRequest request, HttpResponse response, int statusCode, int length, String body, long elapsedMs, String notes) {
        this.probed = true;
        this.probeRequest = request;
        this.probeResponse = response;
        this.probeStatusCode = statusCode;
        this.probeResponseLength = length;
        this.probeResponseBody = body != null ? body : "";
        this.probeResponseTimeMs = elapsedMs;
        this.probeNotes = notes != null ? notes : "";
    }

    public void clearProbe() {
        this.probed = false;
        this.probeStatusCode = -1;
        this.probeResponseLength = 0;
        this.probeResponseBody = "";
        this.probeResponseTimeMs = 0;
        this.probeRequest = null;
        this.probeResponse = null;
        this.probeNotes = "";
    }
}
