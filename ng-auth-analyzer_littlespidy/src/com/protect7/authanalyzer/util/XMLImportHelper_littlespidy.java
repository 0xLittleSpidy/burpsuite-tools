// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.util;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;
import com.protect7.authanalyzer.entities.CustomHttpService_littlespidy;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;

public class XMLImportHelper_littlespidy {

	public static class ParseResult {
		public final List<OriginalRequestResponse> originals = new ArrayList<OriginalRequestResponse>();
		public final List<Session> sessions = new ArrayList<Session>();
	}

	public static ParseResult parseXML(File file) throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		try {
			dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
			dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
		} catch (Throwable ignored) {}

		DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(file);
		doc.getDocumentElement().normalize();

		NodeList messageNodes = doc.getElementsByTagName("Message");
		ParseResult result = new ParseResult();
		LinkedHashSet<String> sessionPrefixes = new LinkedHashSet<String>();
		List<Map<String, String>> messagesData = new ArrayList<Map<String, String>>();

		for (int i = 0; i < messageNodes.getLength(); i++) {
			Node node = messageNodes.item(i);
			if (node.getNodeType() == Node.ELEMENT_NODE) {
				Element el = (Element) node;
				Map<String, String> fieldMap = new LinkedHashMap<String, String>();
				NodeList children = el.getChildNodes();
				for (int j = 0; j < children.getLength(); j++) {
					Node child = children.item(j);
					if (child.getNodeType() == Node.ELEMENT_NODE) {
						String tag = child.getNodeName();
						String text = child.getTextContent();
						fieldMap.put(tag, text);
						if (tag.endsWith("_Bypass_Status")) {
							String prefix = tag.substring(0, tag.length() - "_Bypass_Status".length());
							if (!prefix.equalsIgnoreCase("Original")) {
								sessionPrefixes.add(prefix);
							}
						}
					}
				}
				messagesData.add(fieldMap);
			}
		}

		Map<String, Session> sessionMap = new LinkedHashMap<String, Session>();
		for (String prefix : sessionPrefixes) {
			String displayName = prefix.replace("_", " ");
			Session session = new Session(displayName);
			result.sessions.add(session);
			sessionMap.put(prefix, session);
		}

		int fallbackId = 1;
		for (Map<String, String> fields : messagesData) {
			int id = fallbackId++;
			if (fields.containsKey("ID")) {
				try {
					id = Integer.parseInt(fields.get("ID").trim());
				} catch (Exception ignored) {}
			}
			String method = fields.getOrDefault("Method", "GET");
			String host = fields.getOrDefault("Host", "localhost");
			String path = fields.getOrDefault("Path", "/");
			String comment = fields.getOrDefault("Comment", "");

			int origStatus = parseIntSafe(fields.get("Original_Status_Code"), 200);
			int origLength = parseIntSafe(fields.get("Original_Length"), -1);
			if (origLength == -1 && fields.containsKey("Original_Content_Length")) {
				origLength = parseIntSafe(fields.get("Original_Content_Length"), -1);
			}

			byte[] origReqBytes = decodePayload(fields.get("Original_Request"));
			byte[] origRespBytes = decodePayload(fields.get("Original_Response"));

			CustomHttpService_littlespidy service = new CustomHttpService_littlespidy(host, 443, "https");
			CustomHttpRequestResponse_littlespidy origReqResp = new CustomHttpRequestResponse_littlespidy(origReqBytes, origRespBytes, service);
			origReqResp.setComment(comment);

			OriginalRequestResponse origItem = new OriginalRequestResponse(id, origReqResp, method, path, "", origStatus, origLength);
			origItem.setComment(comment);
			result.originals.add(origItem);

			for (String prefix : sessionPrefixes) {
				Session session = sessionMap.get(prefix);
				String statusVal = fields.get(prefix + "_Bypass_Status");
				BypassConstants status = parseBypassStatus(statusVal);
				int sCode = parseIntSafe(fields.get(prefix + "_Status_Code"), -1);
				int sLen = parseIntSafe(fields.get(prefix + "_Length"), -1);
				if (sLen == -1 && fields.containsKey(prefix + "_Content_Length")) {
					sLen = parseIntSafe(fields.get(prefix + "_Content_Length"), -1);
				}
				byte[] sReq = decodePayload(fields.get(prefix + "_Request"));
				byte[] sResp = decodePayload(fields.get(prefix + "_Response"));

				CustomHttpRequestResponse_littlespidy sReqResp = new CustomHttpRequestResponse_littlespidy(sReq, sResp, service);
				AnalyzerRequestResponse analyzerReqResp = new AnalyzerRequestResponse(sReqResp, status, "", sCode, sLen);
				session.getRequestResponseMap().put(id, analyzerReqResp);
			}
		}

		return result;
	}

	public static BypassConstants parseBypassStatus(String val) {
		if (val == null || val.trim().isEmpty()) {
			return BypassConstants.NA;
		}
		String clean = val.trim().toUpperCase();
		if (clean.equals("SAME") || clean.equals("BYPASSED")) {
			return BypassConstants.SAME;
		}
		if (clean.equals("SIMILAR") || clean.equals("POTENTIAL")) {
			return BypassConstants.SIMILAR;
		}
		if (clean.equals("DIFFERENT") || clean.equals("NOT BYPASSED")) {
			return BypassConstants.DIFFERENT;
		}
		return BypassConstants.NA;
	}

	public static byte[] decodePayload(String text) {
		if (text == null) {
			return new byte[0];
		}
		String trimmed = text.trim();
		if (!trimmed.isEmpty() && !trimmed.contains("\n") && !trimmed.contains("\r")
				&& trimmed.matches("^[A-Za-z0-9+/=]+$") && trimmed.length() % 4 == 0) {
			try {
				byte[] decoded = Base64.getDecoder().decode(trimmed);
				if (decoded != null && decoded.length > 0) {
					return decoded;
				}
			} catch (Exception ignored) {}
		}
		return text.getBytes(StandardCharsets.UTF_8);
	}

	public static int parseIntSafe(String val, int defaultVal) {
		if (val != null) {
			try {
				return Integer.parseInt(val.trim());
			} catch (Exception ignored) {}
		}
		return defaultVal;
	}
}
