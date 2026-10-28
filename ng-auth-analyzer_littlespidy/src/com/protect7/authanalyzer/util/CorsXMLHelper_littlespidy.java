// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.util;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import burp.IHttpRequestResponse;
import com.protect7.authanalyzer.cors.CorsTestResult_littlespidy;

public class CorsXMLHelper_littlespidy {

	public static boolean exportToXML(File file, List<CorsTestResult_littlespidy> results) {
		try (FileWriter writer = new FileWriter(file, StandardCharsets.UTF_8)) {
			writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
			writer.write("<CorsResults>\n");
			for (CorsTestResult_littlespidy res : results) {
				writer.write("  <CorsTestResult>\n");
				writer.write("    <ID>" + res.getId() + "</ID>\n");
				writer.write("    <Method><![CDATA[" + escapeCdata(res.getMethod()) + "]]></Method>\n");
				writer.write("    <Host><![CDATA[" + escapeCdata(res.getHost()) + "]]></Host>\n");
				writer.write("    <Path><![CDATA[" + escapeCdata(res.getPath()) + "]]></Path>\n");
				writer.write("    <OriginPayload><![CDATA[" + escapeCdata(res.getTestedOrigin()) + "]]></OriginPayload>\n");
				writer.write("    <TestType><![CDATA[" + escapeCdata(res.getTestTypeDescription()) + "]]></TestType>\n");
				writer.write("    <StatusCode>" + res.getStatusCode() + "</StatusCode>\n");
				writer.write("    <Length>" + res.getLength() + "</Length>\n");
				writer.write("    <ACAO><![CDATA[" + escapeCdata(res.getReflectedAcao()) + "]]></ACAO>\n");
				writer.write("    <ACAC>" + res.isAcacPresent() + "</ACAC>\n");
				writer.write("    <Severity><![CDATA[" + (res.getSeverity() != null ? res.getSeverity().getName() : "") + "]]></Severity>\n");

				IHttpRequestResponse reqResp = res.getRequestResponse();
				if (reqResp != null) {
					String reqBase64 = (reqResp.getRequest() != null) ? Base64.getEncoder().encodeToString(reqResp.getRequest()) : "";
					String respBase64 = (reqResp.getResponse() != null) ? Base64.getEncoder().encodeToString(reqResp.getResponse()) : "";
					writer.write("    <Request base64=\"true\"><![CDATA[" + reqBase64 + "]]></Request>\n");
					writer.write("    <Response base64=\"true\"><![CDATA[" + respBase64 + "]]></Response>\n");
				} else {
					writer.write("    <Request base64=\"true\"><![CDATA[]]></Request>\n");
					writer.write("    <Response base64=\"true\"><![CDATA[]]></Response>\n");
				}
				writer.write("  </CorsTestResult>\n");
			}
			writer.write("</CorsResults>\n");
			return true;
		} catch (Exception ex) {
			ex.printStackTrace();
			return false;
		}
	}

	private static String escapeCdata(String val) {
		if (val == null) {
			return "";
		}
		return val.replace("]]>", "]]]]><![CDATA[>");
	}
}
