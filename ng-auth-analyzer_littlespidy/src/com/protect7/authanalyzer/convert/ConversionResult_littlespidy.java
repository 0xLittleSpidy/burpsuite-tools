// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.convert;

import burp.IHttpRequestResponse;

/**
 * Encapsulates the result of converting a POST request to GET and testing the server response.
 *
 * @author littlespidy
 */
public class ConversionResult_littlespidy {

	private final int id;
	private final String method;
	private final String host;
	private final String path;
	private final int postStatus;
	private final int getStatus;
	private final int postLength;
	private final int getLength;
	private final String contentType;
	private final String signal;
	private final String severity;
	private final String evidence;
	private final IHttpRequestResponse originalRequestResponse;
	private final IHttpRequestResponse convertedRequestResponse;

	public ConversionResult_littlespidy(int id, String method, String host, String path,
			int postStatus, int getStatus, int postLength, int getLength,
			String contentType, String signal, String severity, String evidence,
			IHttpRequestResponse originalRequestResponse,
			IHttpRequestResponse convertedRequestResponse) {
		this.id = id;
		this.method = method != null ? method : "GET";
		this.host = host != null ? host : "";
		this.path = path != null ? path : "/";
		this.postStatus = postStatus;
		this.getStatus = getStatus;
		this.postLength = postLength;
		this.getLength = getLength;
		this.contentType = contentType != null ? contentType : "";
		this.signal = signal != null ? signal : "";
		this.severity = severity != null ? severity : "Info";
		this.evidence = evidence != null ? evidence : "";
		this.originalRequestResponse = originalRequestResponse;
		this.convertedRequestResponse = convertedRequestResponse;
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

	public int getPostStatus() {
		return postStatus;
	}

	public int getGetStatus() {
		return getStatus;
	}

	public int getPostLength() {
		return postLength;
	}

	public int getGetLength() {
		return getLength;
	}

	public String getContentType() {
		return contentType;
	}

	public String getSignal() {
		return signal;
	}

	public String getSeverity() {
		return severity;
	}

	public String getEvidence() {
		return evidence;
	}

	public IHttpRequestResponse getOriginalRequestResponse() {
		return originalRequestResponse;
	}

	public IHttpRequestResponse getConvertedRequestResponse() {
		return convertedRequestResponse;
	}
}
