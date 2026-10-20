// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.cors;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import com.protect7.authanalyzer.cors.CorsTestResult_littlespidy.CorsSeverity;
import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;

public class CorsEngine_littlespidy {

	public static class TestVector {
		public final String origin;
		public final String description;

		public TestVector(String origin, String description) {
			this.origin = origin;
			this.description = description;
		}
	}

	public static List<TestVector> generateTestVectors(String baseUrl, String attackerUrl) {
		List<TestVector> vectors = new ArrayList<TestVector>();
		if (attackerUrl == null || attackerUrl.trim().isEmpty()) {
			attackerUrl = "evil.com";
		}
		attackerUrl = attackerUrl.trim();
		if (attackerUrl.startsWith("http://")) {
			attackerUrl = attackerUrl.substring(7);
		} else if (attackerUrl.startsWith("https://")) {
			attackerUrl = attackerUrl.substring(8);
		}

		if (baseUrl == null || baseUrl.trim().isEmpty()) {
			baseUrl = "example.com";
		}
		baseUrl = baseUrl.trim();

		// 1. Arbitrary reflection
		vectors.add(new TestVector("https://" + attackerUrl, "Arbitrary Origin Reflection"));

		// 2. Trust HTTP
		vectors.add(new TestVector("http://" + baseUrl, "Trust Insecure HTTP"));

		// 3. Null origin
		vectors.add(new TestVector("null", "Null Origin Trust"));

		// 4. Prefix match: https://example.com.evil.com
		vectors.add(new TestVector("https://" + baseUrl + "." + attackerUrl, "Prefix Match (subdomain of attacker)"));

		// 5. Suffix match: https://examplecomevil.com
		vectors.add(new TestVector("https://" + baseUrl + attackerUrl, "Suffix Match (domain registration)"));

		// 6. Subdomain match: https://subdomain.example.com
		vectors.add(new TestVector("https://subdomain." + baseUrl, "Trust Arbitrary Subdomain"));

		// 7. Substring match: https://example.co
		if (baseUrl.length() > 3) {
			vectors.add(new TestVector("https://" + baseUrl.substring(0, baseUrl.length() - 1), "Substring Match"));
		}

		// 8. Underscore bypass: https://example.com_evil.com
		vectors.add(new TestVector("https://" + baseUrl + "_" + attackerUrl, "Underscore Bypass"));

		// 9. Unescaped dot regex bypass: e.g. www.example.com -> wwwxexample.com
		int firstDot = baseUrl.indexOf('.');
		if (firstDot > 0 && baseUrl.lastIndexOf('.') > firstDot) {
			String regexBypass = baseUrl.substring(0, firstDot) + "x" + baseUrl.substring(firstDot + 1);
			vectors.add(new TestVector("https://" + regexBypass, "Unescaped Dot Regex Bypass"));
		}

		return vectors;
	}

	public static List<CorsTestResult_littlespidy> executeCorsTests(IHttpRequestResponse messageInfo,
			String attackerUrl, IBurpExtenderCallbacks callbacks, int startId) {
		List<CorsTestResult_littlespidy> results = new ArrayList<CorsTestResult_littlespidy>();
		if (messageInfo == null || messageInfo.getRequest() == null) {
			return results;
		}

		byte[] requestBytes = messageInfo.getRequest();
		IHttpService service = messageInfo.getHttpService();
		String host = service != null ? service.getHost() : "unknown";

		IRequestInfo analyzedRequest = null;
		if (callbacks != null && callbacks.getHelpers() != null) {
			analyzedRequest = callbacks.getHelpers().analyzeRequest(service, requestBytes);
		}

		String method = analyzedRequest != null ? analyzedRequest.getMethod() : "GET";
		String path = "/";
		if (analyzedRequest != null && analyzedRequest.getUrl() != null) {
			path = analyzedRequest.getUrl().getPath();
			if (analyzedRequest.getUrl().getQuery() != null) {
				path += "?" + analyzedRequest.getUrl().getQuery();
			}
		}

		// 1. Evaluate original request
		int currentId = startId;
		if (messageInfo.getResponse() != null) {
			CorsTestResult_littlespidy origResult = evaluateResponse(currentId++, method, host, path,
					"None (Original)", "Original Request / Response", messageInfo, callbacks);
			results.add(origResult);
		}

		List<TestVector> vectors = generateTestVectors(host, attackerUrl);
		for (TestVector vector : vectors) {
			try {
				byte[] modifiedRequest = createRequestWithOrigin(requestBytes, vector.origin, callbacks);
				IHttpRequestResponse executed = null;
				if (callbacks != null && service != null) {
					executed = callbacks.makeHttpRequest(service, modifiedRequest);
				} else {
					executed = new CustomHttpRequestResponse_littlespidy(modifiedRequest, new byte[0], service);
				}

				CorsTestResult_littlespidy res = evaluateResponse(currentId++, method, host, path,
						vector.origin, vector.description, executed, callbacks);
				results.add(res);

				// Report scan issue if high severity and callbacks present
				if (callbacks != null && (res.getSeverity() == CorsSeverity.HIGH || res.getSeverity() == CorsSeverity.MEDIUM)) {
					reportScanIssue(callbacks, res, analyzedRequest != null ? analyzedRequest.getUrl() : null);
				}
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}

		return results;
	}

	public static byte[] createRequestWithOrigin(byte[] originalRequest, String origin, IBurpExtenderCallbacks callbacks) {
		if (callbacks == null || callbacks.getHelpers() == null) {
			return originalRequest;
		}
		IRequestInfo info = callbacks.getHelpers().analyzeRequest(originalRequest);
		List<String> headers = new ArrayList<String>();
		for (String header : info.getHeaders()) {
			if (!header.toLowerCase(Locale.ROOT).startsWith("origin:")) {
				headers.add(header);
			}
		}
		headers.add("Origin: " + origin);
		byte[] body = Arrays.copyOfRange(originalRequest, info.getBodyOffset(), originalRequest.length);
		return callbacks.getHelpers().buildHttpMessage(headers, body);
	}

	public static CorsTestResult_littlespidy evaluateResponse(int id, String method, String host, String path,
			String testedOrigin, String description, IHttpRequestResponse message, IBurpExtenderCallbacks callbacks) {
		byte[] response = message.getResponse();
		if (response == null || response.length == 0 || callbacks == null || callbacks.getHelpers() == null) {
			return new CorsTestResult_littlespidy(id, method, host, path, testedOrigin, description, "",
					false, 0, 0, CorsSeverity.SECURE, message);
		}

		IResponseInfo respInfo = callbacks.getHelpers().analyzeResponse(response);
		int statusCode = respInfo.getStatusCode();
		int length = response.length;
		String acao = "";
		boolean acac = false;

		for (String header : respInfo.getHeaders()) {
			String lower = header.toLowerCase(Locale.ROOT);
			if (lower.startsWith("access-control-allow-origin:")) {
				acao = header.substring(header.indexOf(':') + 1).trim();
			} else if (lower.startsWith("access-control-allow-credentials:")) {
				String val = header.substring(header.indexOf(':') + 1).trim();
				if (val.equalsIgnoreCase("true")) {
					acac = true;
				}
			}
		}

		CorsSeverity severity = CorsSeverity.SECURE;
		boolean originReflected = !acao.isEmpty() && (acao.equalsIgnoreCase(testedOrigin) ||
				(!testedOrigin.equals("None (Original)") && acao.replace(" ", "").contains(testedOrigin.replace(" ", ""))));

		if (originReflected && acac) {
			severity = CorsSeverity.HIGH;
		} else if (originReflected) {
			severity = CorsSeverity.MEDIUM;
		} else if (acao.equals("*") && acac) {
			severity = CorsSeverity.HIGH;
		} else if (acao.equals("*")) {
			severity = CorsSeverity.LOW;
		} else if (!acao.isEmpty()) {
			severity = CorsSeverity.LOW;
		}

		return new CorsTestResult_littlespidy(id, method, host, path, testedOrigin, description, acao,
				acac, statusCode, length, severity, message);
	}

	private static void reportScanIssue(IBurpExtenderCallbacks callbacks, CorsTestResult_littlespidy result, URL url) {
		if (url == null || callbacks == null) return;
		try {
			String severityStr = result.getSeverity() == CorsSeverity.HIGH ? "High" : "Medium";
			String detail = "The following Origin was reflected in Access-Control-Allow-Origin: <b>\"" +
					result.getReflectedAcao() + "\"</b> when testing vector <i>" + result.getTestTypeDescription() +
					"</i> (" + result.getTestedOrigin() + ").<br>" +
					(result.isAcacPresent() ? "Additionally, <b>Access-Control-Allow-Credentials: true</b> was set." : "");

			CorsScanIssue issue = new CorsScanIssue(
					result.getRequestResponse().getHttpService(),
					url,
					new IHttpRequestResponse[] { result.getRequestResponse() },
					"CORS: Cross-Origin Resource Sharing Misconfiguration",
					detail,
					severityStr,
					"Certain",
					"Rather than programmatically reflecting the supplied Origin header, use a strict whitelist of trusted domains without wildcards or regex flaws."
			);
			callbacks.addScanIssue(issue);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private static class CorsScanIssue implements IScanIssue {
		private final IHttpService httpService;
		private final URL url;
		private final IHttpRequestResponse[] messages;
		private final String name;
		private final String detail;
		private final String severity;
		private final String confidence;
		private final String remediation;

		public CorsScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] messages,
				String name, String detail, String severity, String confidence, String remediation) {
			this.httpService = httpService;
			this.url = url;
			this.messages = messages;
			this.name = name;
			this.detail = detail;
			this.severity = severity;
			this.confidence = confidence;
			this.remediation = remediation;
		}

		@Override
		public URL getUrl() { return url; }
		@Override
		public String getIssueName() { return name; }
		@Override
		public int getIssueType() { return 0x08000000; }
		@Override
		public String getSeverity() { return severity; }
		@Override
		public String getConfidence() { return confidence; }
		@Override
		public String getIssueBackground() { return "Cross-Origin Resource Sharing (CORS) allows browsers to make cross-domain HTTP requests."; }
		@Override
		public String getRemediationBackground() { return null; }
		@Override
		public String getIssueDetail() { return detail; }
		@Override
		public String getRemediationDetail() { return remediation; }
		@Override
		public IHttpRequestResponse[] getHttpMessages() { return messages; }
		@Override
		public IHttpService getHttpService() { return httpService; }
	}
}
