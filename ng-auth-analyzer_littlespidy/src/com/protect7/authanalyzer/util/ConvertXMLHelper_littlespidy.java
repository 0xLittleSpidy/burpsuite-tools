// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.util;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import com.protect7.authanalyzer.convert.ConversionResult_littlespidy;
import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;
import com.protect7.authanalyzer.entities.CustomHttpService_littlespidy;

public class ConvertXMLHelper_littlespidy {

	public static boolean exportToXML(File file, List<ConversionResult_littlespidy> results) {
		try (FileWriter writer = new FileWriter(file, StandardCharsets.UTF_8)) {
			writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
			writer.write("<ConvertPostToGetResults>\n");
			for (ConversionResult_littlespidy res : results) {
				writer.write("  <ConversionResult>\n");
				writer.write("    <ID>" + res.getId() + "</ID>\n");
				writer.write("    <Method><![CDATA[" + res.getMethod() + "]]></Method>\n");
				writer.write("    <Host><![CDATA[" + res.getHost() + "]]></Host>\n");
				writer.write("    <Path><![CDATA[" + res.getPath() + "]]></Path>\n");
				writer.write("    <PostStatus>" + res.getPostStatus() + "</PostStatus>\n");
				writer.write("    <GetStatus>" + res.getGetStatus() + "</GetStatus>\n");
				writer.write("    <PostLength>" + res.getPostLength() + "</PostLength>\n");
				writer.write("    <GetLength>" + res.getGetLength() + "</GetLength>\n");
				writer.write("    <ContentType><![CDATA[" + res.getContentType() + "]]></ContentType>\n");
				writer.write("    <Signal><![CDATA[" + res.getSignal() + "]]></Signal>\n");
				writer.write("    <Severity><![CDATA[" + res.getSeverity() + "]]></Severity>\n");

				IHttpRequestResponse orig = res.getOriginalRequestResponse();
				if (orig != null) {
					writer.write("    <OriginalRequest><![CDATA[" + (orig.getRequest() != null ? Base64.getEncoder().encodeToString(orig.getRequest()) : "") + "]]></OriginalRequest>\n");
					writer.write("    <OriginalResponse><![CDATA[" + (orig.getResponse() != null ? Base64.getEncoder().encodeToString(orig.getResponse()) : "") + "]]></OriginalResponse>\n");
				}

				IHttpRequestResponse conv = res.getConvertedRequestResponse();
				if (conv != null) {
					writer.write("    <ConvertedRequest><![CDATA[" + (conv.getRequest() != null ? Base64.getEncoder().encodeToString(conv.getRequest()) : "") + "]]></ConvertedRequest>\n");
					writer.write("    <ConvertedResponse><![CDATA[" + (conv.getResponse() != null ? Base64.getEncoder().encodeToString(conv.getResponse()) : "") + "]]></ConvertedResponse>\n");
				}
				writer.write("  </ConversionResult>\n");
			}
			writer.write("</ConvertPostToGetResults>\n");
			return true;
		} catch (Exception ex) {
			ex.printStackTrace();
			return false;
		}
	}

	public static List<ConversionResult_littlespidy> importFromXML(File file) throws Exception {
		List<ConversionResult_littlespidy> list = new ArrayList<ConversionResult_littlespidy>();
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(file);
		doc.getDocumentElement().normalize();

		NodeList nodes = doc.getElementsByTagName("ConversionResult");
		for (int i = 0; i < nodes.getLength(); i++) {
			Element el = (Element) nodes.item(i);
			int id = getIntVal(el, "ID", i + 1);
			String method = getTextVal(el, "Method", "POST");
			String host = getTextVal(el, "Host", "");
			String path = getTextVal(el, "Path", "/");
			int postStatus = getIntVal(el, "PostStatus", 0);
			int getStatus = getIntVal(el, "GetStatus", 0);
			int postLen = getIntVal(el, "PostLength", 0);
			int getLen = getIntVal(el, "GetLength", 0);
			String contentType = getTextVal(el, "ContentType", "");
			String signal = getTextVal(el, "Signal", "");
			String severity = getTextVal(el, "Severity", "Low");

			byte[] origReq = decodeBase64(getTextVal(el, "OriginalRequest", ""));
			byte[] origResp = decodeBase64(getTextVal(el, "OriginalResponse", ""));
			byte[] convReq = decodeBase64(getTextVal(el, "ConvertedRequest", ""));
			byte[] convResp = decodeBase64(getTextVal(el, "ConvertedResponse", ""));

			IHttpService service = new CustomHttpService_littlespidy(host, 443, "https");
			IHttpRequestResponse orig = new CustomHttpRequestResponse_littlespidy(origReq, origResp, service);
			IHttpRequestResponse conv = new CustomHttpRequestResponse_littlespidy(convReq, convResp, service);

			ConversionResult_littlespidy res = new ConversionResult_littlespidy(
					id, method, host, path, postStatus, getStatus, postLen, getLen,
					contentType, signal, severity, "", orig, conv);
			list.add(res);
		}
		return list;
	}

	private static String getTextVal(Element parent, String tag, String def) {
		NodeList nl = parent.getElementsByTagName(tag);
		if (nl != null && nl.getLength() > 0 && nl.item(0) != null) {
			return nl.item(0).getTextContent();
		}
		return def;
	}

	private static int getIntVal(Element parent, String tag, int def) {
		try {
			String t = getTextVal(parent, tag, null);
			return t != null ? Integer.parseInt(t.trim()) : def;
		} catch (Exception e) {
			return def;
		}
	}

	private static byte[] decodeBase64(String val) {
		if (val == null || val.trim().isEmpty()) {
			return new byte[0];
		}
		try {
			return Base64.getDecoder().decode(val.trim());
		} catch (Exception e) {
			return new byte[0];
		}
	}
}
