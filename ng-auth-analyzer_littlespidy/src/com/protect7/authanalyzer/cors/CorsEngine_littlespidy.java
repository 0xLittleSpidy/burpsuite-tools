// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.cors;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
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
		public final String id;
		public final String name;
		public final String origin;
		public final String description;
		public final String browserNote;

		public TestVector(String id, String name, String origin, String description, String browserNote) {
			this.id = id;
			this.name = name;
			this.origin = origin;
			this.description = description;
			this.browserNote = browserNote;
		}

		public TestVector(String origin, String description) {
			this(description, description, origin, description, "");
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
		if (baseUrl.startsWith("http://")) {
			baseUrl = baseUrl.substring(7);
		} else if (baseUrl.startsWith("https://")) {
			baseUrl = baseUrl.substring(8);
		}
		if (baseUrl.contains("/")) {
			baseUrl = baseUrl.substring(0, baseUrl.indexOf('/'));
		}
		if (baseUrl.contains(":")) {
			baseUrl = baseUrl.substring(0, baseUrl.indexOf(':'));
		}

		// PortSwigger 29 CORS Bypass Techniques
		// 1. Dot-Underscore-Dot Subdomain
		vectors.add(new TestVector("dot_underscore_dot", "Dot-Underscore-Dot Subdomain",
				"https://" + baseUrl + "._." + attackerUrl, "Underscore subdomain bypass", "Bypasses naive domain regex matching"));

		// 2. Dot-Hyphen-Dot Subdomain
		vectors.add(new TestVector("dot_hyphen_dot", "Dot-Hyphen-Dot Subdomain",
				"https://" + baseUrl + ".-." + attackerUrl, "Hyphen subdomain bypass", "Bypasses subdomain regex"));

		// 3. Safari Comma Subdomain
		vectors.add(new TestVector("safari_comma", "Safari Comma Subdomain",
				"https://" + baseUrl + ".,." + attackerUrl, "Safari allows comma in subdomain", "Safari browser specific"));

		// 4. Safari Semicolon Subdomain
		vectors.add(new TestVector("safari_semicolon", "Safari Semicolon Subdomain",
				"https://" + baseUrl + ".;." + attackerUrl, "Safari allows semicolon in subdomain", "Safari browser specific"));

		// 5. Safari Exclamation Subdomain
		vectors.add(new TestVector("safari_exclamation", "Safari Exclamation Subdomain",
				"https://" + baseUrl + ".!." + attackerUrl, "Safari allows exclamation mark in subdomain", "Safari browser specific"));

		// 6. Safari Single Quote Subdomain
		vectors.add(new TestVector("safari_single_quote", "Safari Single Quote Subdomain",
				"https://" + baseUrl + ".'." + attackerUrl, "Safari allows single quote in subdomain", "Safari browser specific"));

		// 7. Safari Open Parenthesis
		vectors.add(new TestVector("safari_open_paren", "Safari Open Parenthesis",
				"https://" + baseUrl + ".(." + attackerUrl, "Safari allows open parenthesis in subdomain", "Safari browser specific"));

		// 8. Safari Close Parenthesis
		vectors.add(new TestVector("safari_close_paren", "Safari Close Parenthesis",
				"https://" + baseUrl + ".)." + attackerUrl, "Safari allows close parenthesis in subdomain", "Safari browser specific"));

		// 9. Safari Open Brace
		vectors.add(new TestVector("safari_open_brace", "Safari Open Brace",
				"https://" + baseUrl + ".{." + attackerUrl, "Safari allows open brace in subdomain", "Safari browser specific"));

		// 10. Safari Close Brace
		vectors.add(new TestVector("safari_close_brace", "Safari Close Brace",
				"https://" + baseUrl + ".}." + attackerUrl, "Safari allows close brace in subdomain", "Safari browser specific"));

		// 11. Safari Asterisk Subdomain
		vectors.add(new TestVector("safari_asterisk", "Safari Asterisk Subdomain",
				"https://" + baseUrl + ".*." + attackerUrl, "Safari allows asterisk in subdomain", "Safari browser specific"));

		// 12. Safari Ampersand Subdomain
		vectors.add(new TestVector("safari_ampersand", "Safari Ampersand Subdomain",
				"https://" + baseUrl + ".&." + attackerUrl, "Safari allows ampersand in subdomain", "Safari browser specific"));

		// 13. Safari Backtick Subdomain
		vectors.add(new TestVector("safari_backtick", "Safari Backtick Subdomain",
				"https://" + baseUrl + ".`." + attackerUrl, "Safari allows backtick in subdomain", "Safari browser specific"));

		// 14. Firefox & Safari Plus Subdomain
		vectors.add(new TestVector("firefox_safari_plus", "Firefox & Safari Plus Subdomain",
				"https://" + baseUrl + ".+." + attackerUrl, "Firefox & Safari allow plus in subdomain", "Firefox & Safari browser specific"));

		// 15. Prefix Match / Attacker Subdomain
		vectors.add(new TestVector("prefix_match", "Prefix Match / Attacker Subdomain",
				"https://" + baseUrl + "." + attackerUrl, "Regex prefix match without dot anchor", "Common regex error"));

		// 16. Safari Equals Subdomain
		vectors.add(new TestVector("safari_equals", "Safari Equals Subdomain",
				"https://" + baseUrl + ".=." + attackerUrl, "Safari allows equals in subdomain", "Safari browser specific"));

		// 17. Safari Tilde Subdomain
		vectors.add(new TestVector("safari_tilde", "Safari Tilde Subdomain",
				"https://" + baseUrl + ".~." + attackerUrl, "Safari allows tilde in subdomain", "Safari browser specific"));

		// 18. Firefox & Safari Dollar Subdomain
		vectors.add(new TestVector("firefox_safari_dollar", "Firefox & Safari Dollar Subdomain",
				"https://" + baseUrl + ".$.+" + attackerUrl, "Firefox & Safari allow dollar in subdomain", "Firefox & Safari browser specific"));

		// 19. Suffix Match (Domain Registration)
		vectors.add(new TestVector("suffix_match", "Suffix Match (Domain Registration)",
				"https://" + baseUrl + attackerUrl, "Attacker registers domain ending with allowed domain", "Regex suffix match without boundary"));

		// 20. Trust Arbitrary Subdomain
		vectors.add(new TestVector("trust_subdomain", "Trust Arbitrary Subdomain",
				"https://" + attackerUrl + "." + baseUrl, "Insecure wildcard subdomain trust", "Subdomain takeover risk"));

		// 21. Domain Ends With
		vectors.add(new TestVector("ends_with", "Domain Ends With",
				"https://anything" + baseUrl, "Unanchored regex matching end of string", "Unanchored regex"));

		// 22. Localhost Regex Edge Case
		vectors.add(new TestVector("localhost_edge", "Localhost Regex Edge Case",
				"https://localhost." + attackerUrl, "Localhost regex implementation edge case", "Regex matches localhost without anchor"));

		// 23. Trusted Null Origin
		vectors.add(new TestVector("trusted_null", "Trusted Null Origin",
				"null", "CORS vulnerability with trusted null origin", "Sandboxed iframe / data URI exploitation"));

		// 24. Unencrypted Ends With
		vectors.add(new TestVector("unencrypted_ends_with", "Unencrypted Domain Ends With",
				"http://s" + baseUrl, "Unencrypted domain ends with http://s<allowed>", "Insecure HTTP scheme bypass"));

		// 25. IPv6 Localhost Loopback
		vectors.add(new TestVector("ipv6_unspecified", "IPv6 Localhost Loopback",
				"http://[::]", "IPv6 unspecified address loopback", "Server trusts loopback origin"));

		// 26. IPv6 Loopback
		vectors.add(new TestVector("ipv6_loopback", "IPv6 Loopback",
				"http://[::1]", "Standard IPv6 loopback", "Server trusts loopback origin"));

		// 27. IPv4-Mapped IPv6 Loopback
		vectors.add(new TestVector("ipv4_mapped_ipv6", "IPv4-Mapped IPv6 Loopback",
				"http://[::ffff:7f00:1]", "IPv4-mapped 127.0.0.1 loopback", "Server trusts loopback origin"));

		// 28. Fully-Expanded IPv6 Loopback
		vectors.add(new TestVector("ipv6_expanded", "Fully-Expanded IPv6 Loopback",
				"http://[0000:0000:0000:0000:0000:0000:0000:0000]", "Fully-expanded IPv6 loopback", "Server trusts expanded IPv6"));

		// 29. Local / Localhost Bypass
		vectors.add(new TestVector("localhost_local", "Localhost Allowed Domain Bypass",
				"http://" + baseUrl + ".localhost", "Localhost allowed domain bypass", "Internal domain resolution bypass"));

		return vectors;
	}

	public static List<CorsTestResult_littlespidy> executeCorsTests(IHttpRequestResponse messageInfo,
			String attackerUrl, Set<String> enabledTechniqueIds, IBurpExtenderCallbacks callbacks, int startId) {
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

		int currentId = startId;
		// Evaluate original request
		if (messageInfo.getResponse() != null) {
			CorsTestResult_littlespidy origResult = evaluateResponse(currentId++, method, host, path,
					"None (Original)", "Original Request / Response", messageInfo, callbacks);
			results.add(origResult);
		}

		List<TestVector> vectors = generateTestVectors(host, attackerUrl);
		for (TestVector vector : vectors) {
			if (enabledTechniqueIds != null && !enabledTechniqueIds.isEmpty() && !enabledTechniqueIds.contains(vector.id)) {
				continue;
			}
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

				if (callbacks != null && (res.getSeverity() == CorsSeverity.HIGH || res.getSeverity() == CorsSeverity.MEDIUM)) {
					reportScanIssue(callbacks, res, analyzedRequest != null ? analyzedRequest.getUrl() : null);
				}
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}

		return results;
	}

	public static List<CorsTestResult_littlespidy> executeCorsTests(IHttpRequestResponse messageInfo,
			String attackerUrl, IBurpExtenderCallbacks callbacks, int startId) {
		return executeCorsTests(messageInfo, attackerUrl, null, callbacks, startId);
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

	private static void reportScanIssue(IBurpExtenderCallbacks callbacks, CorsTestResult_littlespidy res, URL url) {
		if (callbacks == null || url == null) {
			return;
		}
		IScanIssue issue = new IScanIssue() {
			@Override
			public URL getUrl() {
				return url;
			}
			@Override
			public String getIssueName() {
				return "CORS Misconfiguration: " + res.getTestTypeDescription();
			}
			@Override
			public int getIssueType() {
				return 0x08000000;
			}
			@Override
			public String getSeverity() {
				return res.getSeverity() == CorsSeverity.HIGH ? "High" : "Medium";
			}
			@Override
			public String getConfidence() {
				return "Certain";
			}
			@Override
			public String getIssueBackground() {
				return "The application specifies insecure Cross-Origin Resource Sharing (CORS) headers.<br>" +
						"Origin: <code>" + res.getTestedOrigin() + "</code><br>" +
						"Access-Control-Allow-Origin: <code>" + res.getReflectedAcao() + "</code><br>" +
						"Access-Control-Allow-Credentials: <code>" + res.isAcacPresent() + "</code>";
			}
			@Override
			public String getRemediationBackground() {
				return "Do not trust arbitrary or unvalidated origins. Use a strict whitelist of trusted domains and avoid combining wildcard or arbitrary reflection with Access-Control-Allow-Credentials: true.";
			}
			@Override
			public String getIssueDetail() {
				return "Origin header reflected in ACAO response with credentials: " + res.isAcacPresent();
			}
			@Override
			public String getRemediationDetail() {
				return null;
			}
			@Override
			public IHttpRequestResponse[] getHttpMessages() {
				return new IHttpRequestResponse[] { res.getRequestResponse() };
			}
			@Override
			public IHttpService getHttpService() {
				return res.getRequestResponse() != null ? res.getRequestResponse().getHttpService() : null;
			}
		};
		callbacks.addScanIssue(issue);
	}
}
