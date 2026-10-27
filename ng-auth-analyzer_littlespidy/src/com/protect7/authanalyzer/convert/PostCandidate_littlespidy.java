// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.convert;

import java.util.ArrayList;
import java.util.List;
import burp.IHttpRequestResponse;

/**
 * Represents a discovered POST request candidate for conversion triage.
 *
 * @author littlespidy
 */
public class PostCandidate_littlespidy {

	private final int id;
	private final String method;
	private final String host;
	private final String path;
	private final String url;
	private final String contentType;
	private final int parameterCount;
	private final List<String> parameterNames;
	private final int statusCode;
	private final int contentLength;
	private final String authIndicator;
	private final IHttpRequestResponse requestResponse;

	public PostCandidate_littlespidy(int id, String method, String host, String path, String url,
			String contentType, int parameterCount, List<String> parameterNames,
			int statusCode, int contentLength, String authIndicator,
			IHttpRequestResponse requestResponse) {
		this.id = id;
		this.method = method != null ? method : "POST";
		this.host = host != null ? host : "";
		this.path = path != null ? path : "/";
		this.url = url != null ? url : "";
		this.contentType = contentType != null ? contentType : "";
		this.parameterCount = parameterCount;
		this.parameterNames = parameterNames != null ? parameterNames : new ArrayList<>();
		this.statusCode = statusCode;
		this.contentLength = contentLength;
		this.authIndicator = authIndicator != null ? authIndicator : "None";
		this.requestResponse = requestResponse;
	}

	public int getId() {
		return id;
	}

	public String getMethod() {
		return method;
	}

	public String getHost() {
		return host;
	}

	public String getPath() {
		return path;
	}

	public String getUrl() {
		return url;
	}

	public String getContentType() {
		return contentType;
	}

	public int getParameterCount() {
		return parameterCount;
	}

	public List<String> getParameterNames() {
		return parameterNames;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public int getContentLength() {
		return contentLength;
	}

	public String getAuthIndicator() {
		return authIndicator;
	}

	public IHttpRequestResponse getRequestResponse() {
		return requestResponse;
	}
}
