// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.convert;

import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;

/**
 * Core engine to convert POST requests to GET and evaluate responses for authorization bypasses and CSRF vulnerabilities.
 *
 * @author littlespidy
 */
public class ConvertEngine_littlespidy {

	public static ConversionResult_littlespidy convertAndTest(IHttpRequestResponse messageInfo,
			IBurpExtenderCallbacks callbacks, int resultId) {
		if (messageInfo == null || messageInfo.getRequest() == null || callbacks == null) {
			return null;
		}

		IExtensionHelpers helpers = callbacks.getHelpers();
		IHttpService service = messageInfo.getHttpService();
		byte[] originalRequestBytes = messageInfo.getRequest();
		IRequestInfo requestInfo = helpers.analyzeRequest(service, originalRequestBytes);

		String method = requestInfo.getMethod();
		URL url = requestInfo.getUrl();
		String host = (url != null && url.getHost() != null) ? url.getHost() : (service != null ? service.getHost() : "");
		String path = (url != null && url.getPath() != null) ? url.getPath() : "/";

		int postStatus = 0;
		int postLength = 0;
		if (messageInfo.getResponse() != null) {
			IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());
			postStatus = respInfo.getStatusCode();
			postLength = messageInfo.getResponse().length - respInfo.getBodyOffset();
		}

		// Convert POST to GET request
		byte[] convertedGetRequestBytes = buildGetRequestFromPost(originalRequestBytes, requestInfo, helpers);

		// Execute converted GET request
		IHttpRequestResponse getRequestResponse = callbacks.makeHttpRequest(service, convertedGetRequestBytes);

		int getStatus = 0;
		int getLength = 0;
		String getContentType = "";
		if (getRequestResponse != null && getRequestResponse.getResponse() != null) {
			IResponseInfo getRespInfo = helpers.analyzeResponse(getRequestResponse.getResponse());
			getStatus = getRespInfo.getStatusCode();
			getLength = getRequestResponse.getResponse().length - getRespInfo.getBodyOffset();
			for (String header : getRespInfo.getHeaders()) {
				if (header.toLowerCase(Locale.ROOT).startsWith("content-type:")) {
					getContentType = header.substring(13).trim();
					break;
				}
			}
		}

		// Evaluate Signal and Severity
		String signal = "";
		String severity = "Info";
		String evidence = "";

		boolean isBypass = (postStatus == 401 || postStatus == 403) && (getStatus == 200 || getStatus == 302);
		boolean isServerError = (getStatus >= 500 && getStatus <= 599);
		boolean isMethodPermitted = (getStatus >= 200 && getStatus < 300);
		boolean isMethodNotAllowed = (getStatus == 405 || getStatus == 501);
		boolean isRedirect = (getStatus >= 300 && getStatus < 400);

		if (isBypass) {
			severity = "High";
			signal = "Auth Bypass Detected (POST " + postStatus + " -> GET " + getStatus + ")";
			evidence = "Original POST returned HTTP " + postStatus + " (Blocked). Converted GET returned HTTP " + getStatus + " (Accepted). Possible method confusion or authorization bypass.";
		} else if (isServerError) {
			severity = "Low";
			signal = "Server Error on GET (HTTP " + getStatus + ")";
			evidence = "Converted GET caused backend error/crash (HTTP " + getStatus + ").";
		} else if (isMethodPermitted) {
			severity = "Medium";
			signal = "Method Permitted / CSRF Potential (200 OK)";
			evidence = "Backend accepted the GET method with migrated query parameters. If state-changing, this may permit CSRF without POST token validation.";
		} else if (isMethodNotAllowed) {
			severity = "Info";
			signal = "405 Method Not Allowed";
			evidence = "Server explicitly rejected GET method (HTTP " + getStatus + ").";
		} else if (isRedirect) {
			severity = "Info";
			signal = "Redirect on GET (HTTP " + getStatus + ")";
			evidence = "Converted GET redirected to " + getStatus + ".";
		} else {
			severity = "Info";
			signal = "Status (" + postStatus + " -> " + getStatus + ")";
			evidence = "POST: " + postStatus + " (" + postLength + "B), GET: " + getStatus + " (" + getLength + "B)";
		}

		IRequestInfo convertedRequestInfo = helpers.analyzeRequest(service, convertedGetRequestBytes);
		String newPath = (convertedRequestInfo != null && convertedRequestInfo.getUrl() != null)
				? convertedRequestInfo.getUrl().getFile() : path;

		return new ConversionResult_littlespidy(resultId, "GET", host, newPath,
				postStatus, getStatus, postLength, getLength, getContentType, signal, severity, evidence,
				messageInfo, getRequestResponse);
	}

	public static byte[] buildGetRequestFromPost(byte[] originalRequestBytes, IRequestInfo requestInfo, IExtensionHelpers helpers) {
		int bodyOffset = requestInfo.getBodyOffset();
		String body = "";
		if (originalRequestBytes.length > bodyOffset) {
			body = new String(Arrays.copyOfRange(originalRequestBytes, bodyOffset, originalRequestBytes.length), StandardCharsets.UTF_8).trim();
		}

		List<String> headers = new ArrayList<String>(requestInfo.getHeaders());
		String firstLine = headers.isEmpty() ? "GET / HTTP/1.1" : headers.get(0);
		String contentType = "";

		// Extract Content-Type
		for (String h : headers) {
			if (h.toLowerCase(Locale.ROOT).startsWith("content-type:")) {
				contentType = h.substring(13).trim().toLowerCase(Locale.ROOT);
				break;
			}
		}

		// Convert body parameters into query parameters string
		String bodyParams = extractBodyParametersAsQueryString(body, contentType);

		// Parse URI from first line
		String[] parts = firstLine.split(" ");
		String targetUri = (parts.length > 1) ? parts[1] : "/";
		String httpVersion = (parts.length > 2) ? parts[2] : "HTTP/1.1";

		String basePath = targetUri;
		String existingQuery = "";
		int qIdx = targetUri.indexOf('?');
		if (qIdx >= 0) {
			basePath = targetUri.substring(0, qIdx);
			existingQuery = targetUri.substring(qIdx + 1);
		}

		StringBuilder newUri = new StringBuilder(basePath);
		if (!existingQuery.isEmpty() || !bodyParams.isEmpty()) {
			newUri.append("?");
			if (!existingQuery.isEmpty()) {
				newUri.append(existingQuery);
				if (!bodyParams.isEmpty()) {
					newUri.append("&");
				}
			}
			if (!bodyParams.isEmpty()) {
				newUri.append(bodyParams);
			}
		}

		// Update first line to GET
		headers.set(0, "GET " + newUri.toString() + " " + httpVersion);

		// Remove Content-Type and Content-Length headers
		Iterator<String> it = headers.iterator();
		while (it.hasNext()) {
			String h = it.next().toLowerCase(Locale.ROOT);
			if (h.startsWith("content-type:") || h.startsWith("content-length:")) {
				it.remove();
			}
		}

		return helpers.buildHttpMessage(headers, new byte[0]);
	}

	public static String extractBodyParametersAsQueryString(String body, String contentType) {
		if (body == null || body.trim().isEmpty()) {
			return "";
		}
		body = body.trim();

		if (contentType.contains("application/x-www-form-urlencoded")) {
			return body;
		}

		if (contentType.contains("application/json")) {
			StringBuilder sb = new StringBuilder();
			String stripped = body;
			if (stripped.startsWith("{") && stripped.endsWith("}")) {
				stripped = stripped.substring(1, stripped.length() - 1).trim();
			}

			// Split by top-level commas outside quotes
			String[] pairs = stripped.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
			for (String pair : pairs) {
				pair = pair.trim();
				int colonIdx = pair.indexOf(':');
				if (colonIdx < 0) continue;

				String key = pair.substring(0, colonIdx).trim().replaceAll("^\"|\"$", "");
				String value = pair.substring(colonIdx + 1).trim().replaceAll("^\"|\"$", "");

				if (sb.length() > 0) sb.append("&");
				sb.append(urlEncode(key)).append("=").append(urlEncode(value));
			}
			return sb.toString();
		}

		// Fallback: URL encode non-empty raw body
		return urlEncode(body);
	}

	public static PostCandidate_littlespidy createCandidate(IHttpRequestResponse messageInfo,
			IBurpExtenderCallbacks callbacks, int candidateId) {
		if (messageInfo == null || messageInfo.getRequest() == null || callbacks == null) {
			return null;
		}

		IExtensionHelpers helpers = callbacks.getHelpers();
		IHttpService service = messageInfo.getHttpService();
		IRequestInfo reqInfo = helpers.analyzeRequest(service, messageInfo.getRequest());

		String method = reqInfo.getMethod();
		URL url = reqInfo.getUrl();
		String host = (url != null && url.getHost() != null) ? url.getHost() : (service != null ? service.getHost() : "");
		String path = (url != null && url.getPath() != null) ? url.getPath() : "/";
		String fullUrl = (url != null) ? url.toString() : host + path;

		String contentType = "";
		for (String h : reqInfo.getHeaders()) {
			if (h.toLowerCase(Locale.ROOT).startsWith("content-type:")) {
				contentType = h.substring(13).trim();
				break;
			}
		}

		List<String> paramNames = new ArrayList<String>();
		for (IParameter p : reqInfo.getParameters()) {
			if (p.getType() == IParameter.PARAM_BODY || p.getType() == IParameter.PARAM_JSON || p.getType() == IParameter.PARAM_MULTIPART_ATTR) {
				paramNames.add(p.getName());
			}
		}

		int statusCode = 0;
		int contentLength = 0;
		if (messageInfo.getResponse() != null) {
			IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());
			statusCode = respInfo.getStatusCode();
			contentLength = messageInfo.getResponse().length - respInfo.getBodyOffset();
		}

		String auth = "None";
		for (String h : reqInfo.getHeaders()) {
			String lower = h.toLowerCase(Locale.ROOT);
			if (lower.startsWith("authorization:")) {
				auth = "Authorization Header";
				break;
			} else if (lower.startsWith("cookie:")) {
				auth = "Cookie";
			}
		}

		return new PostCandidate_littlespidy(candidateId, method, host, path, fullUrl, contentType,
				paramNames.size(), paramNames, statusCode, contentLength, auth, messageInfo);
	}

	public static String urlEncode(String text) {
		try {
			return URLEncoder.encode(text, StandardCharsets.UTF_8);
		} catch (Exception e) {
			return text != null ? text : "";
		}
	}
}
