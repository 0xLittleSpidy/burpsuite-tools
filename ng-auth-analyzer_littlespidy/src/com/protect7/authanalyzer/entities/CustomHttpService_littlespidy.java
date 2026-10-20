// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.entities;

import burp.IHttpService;

public class CustomHttpService_littlespidy implements IHttpService {

	private final String host;
	private final int port;
	private final String protocol;

	public CustomHttpService_littlespidy(String host, int port, String protocol) {
		this.host = (host != null && !host.isBlank()) ? host : "localhost";
		this.port = port > 0 ? port : ("https".equalsIgnoreCase(protocol) ? 443 : 80);
		this.protocol = (protocol != null && !protocol.isBlank()) ? protocol.toLowerCase() : (this.port == 443 ? "https" : "http");
	}

	@Override
	public String getHost() {
		return host;
	}

	@Override
	public int getPort() {
		return port;
	}

	@Override
	public String getProtocol() {
		return protocol;
	}

	@Override
	public String toString() {
		return protocol + "://" + host + (port == 80 || port == 443 ? "" : ":" + port);
	}
}
