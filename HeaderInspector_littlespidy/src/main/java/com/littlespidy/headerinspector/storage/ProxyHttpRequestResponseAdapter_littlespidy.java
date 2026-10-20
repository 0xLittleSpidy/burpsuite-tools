// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.headerinspector.storage;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.time.ZonedDateTime;
import java.util.regex.Pattern;

/**
 * Adapter allowing reconstructed HttpRequest and HttpResponse objects to be ingested
 * into Proxy-based collectors during session deserialization.
 */
public class ProxyHttpRequestResponseAdapter_littlespidy implements ProxyHttpRequestResponse {

    private final HttpRequest request;
    private final HttpResponse response;
    private final ZonedDateTime time;

    public ProxyHttpRequestResponseAdapter_littlespidy(HttpRequest request, HttpResponse response, ZonedDateTime time) {
        this.request = request;
        this.response = response;
        this.time = time != null ? time : ZonedDateTime.now();
    }

    @Override public HttpRequest request() { return request; }
    @Override public HttpRequest finalRequest() { return request; }
    @Override public HttpResponse response() { return response; }
    @Override public HttpResponse originalResponse() { return response; }
    @Override public Annotations annotations() { return Annotations.annotations(); }
    @Override public HttpService httpService() { return request != null ? request.httpService() : null; }
    @Override public String url() { return request != null ? request.url() : ""; }
    @Override public String method() { return request != null ? request.method() : "GET"; }
    @Override public String path() { return request != null ? request.path() : "/"; }
    @Override public String host() { return httpService() != null ? httpService().host() : ""; }
    @Override public int port() { return httpService() != null ? httpService().port() : 80; }
    @Override public boolean secure() { return httpService() != null && httpService().secure(); }
    @Override public String httpServiceString() { return httpService() != null ? httpService().toString() : ""; }
    @Override public String requestHttpVersion() { return request != null ? request.httpVersion() : "HTTP/1.1"; }
    @Override public String requestBody() { return request != null ? request.bodyToString() : ""; }
    @Override public boolean edited() { return false; }
    @Override public ZonedDateTime time() { return time; }
    @Override public int listenerPort() { return 8080; }
    @Override public MimeType mimeType() { return response != null ? response.inferredMimeType() : MimeType.NONE; }
    @Override public boolean hasResponse() { return response != null; }
    @Override public boolean contains(String searchTerm, boolean caseSensitive) { return false; }
    @Override public boolean contains(Pattern pattern) { return false; }
    @Override public TimingData timingData() { return null; }
}
