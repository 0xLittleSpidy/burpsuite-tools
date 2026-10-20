// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.cors;

import burp.IHttpRequestResponse;

public class CorsTestResult_littlespidy {

	public enum CorsSeverity {
		HIGH("HIGH"),
		MEDIUM("MEDIUM"),
		LOW("LOW"),
		SECURE("SECURE");

		private final String name;

		CorsSeverity(String name) {
			this.name = name;
		}

		public String getName() {
			return name;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	private final int id;
	private final String method;
	private final String host;
	private final String path;
	private final String testedOrigin;
	private final String testTypeDescription;
	private final String reflectedAcao;
	private final boolean acacPresent;
	private final int statusCode;
	private final int length;
	private final CorsSeverity severity;
	private final IHttpRequestResponse requestResponse;

	public CorsTestResult_littlespidy(int id, String method, String host, String path,
			String testedOrigin, String testTypeDescription, String reflectedAcao,
			boolean acacPresent, int statusCode, int length, CorsSeverity severity,
			IHttpRequestResponse requestResponse) {
		this.id = id;
		this.method = method;
		this.host = host;
		this.path = path;
		this.testedOrigin = testedOrigin;
		this.testTypeDescription = testTypeDescription;
		this.reflectedAcao = reflectedAcao != null ? reflectedAcao : "";
		this.acacPresent = acacPresent;
		this.statusCode = statusCode;
		this.length = length;
		this.severity = severity;
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

	public String getTestedOrigin() {
		return testedOrigin;
	}

	public String getTestTypeDescription() {
		return testTypeDescription;
	}

	public String getReflectedAcao() {
		return reflectedAcao;
	}

	public boolean isAcacPresent() {
		return acacPresent;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public int getLength() {
		return length;
	}

	public CorsSeverity getSeverity() {
		return severity;
	}

	public IHttpRequestResponse getRequestResponse() {
		return requestResponse;
	}
}
