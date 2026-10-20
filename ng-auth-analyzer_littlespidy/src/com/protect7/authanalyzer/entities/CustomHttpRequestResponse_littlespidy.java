// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.entities;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class CustomHttpRequestResponse_littlespidy implements IHttpRequestResponse {

	private byte[] request;
	private byte[] response;
	private String comment = "";
	private String highlight = null;
	private IHttpService httpService;

	public CustomHttpRequestResponse_littlespidy(byte[] request, byte[] response, IHttpService httpService) {
		this.request = request != null ? request : new byte[0];
		this.response = response != null ? response : new byte[0];
		this.httpService = httpService;
	}

	@Override
	public byte[] getRequest() {
		return request;
	}

	@Override
	public void setRequest(byte[] message) {
		this.request = (message != null) ? message : new byte[0];
	}

	@Override
	public byte[] getResponse() {
		return response;
	}

	@Override
	public void setResponse(byte[] message) {
		this.response = (message != null) ? message : new byte[0];
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public void setComment(String comment) {
		this.comment = (comment != null) ? comment : "";
	}

	@Override
	public String getHighlight() {
		return highlight;
	}

	@Override
	public void setHighlight(String color) {
		this.highlight = color;
	}

	@Override
	public IHttpService getHttpService() {
		return httpService;
	}

	@Override
	public void setHttpService(IHttpService httpService) {
		this.httpService = httpService;
	}
}
