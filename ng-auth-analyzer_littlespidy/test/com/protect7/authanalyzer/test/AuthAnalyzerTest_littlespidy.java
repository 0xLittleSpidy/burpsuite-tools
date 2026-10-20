// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.test;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;
import com.protect7.authanalyzer.entities.CustomHttpService_littlespidy;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.main.HistoryPanel_littlespidy;
import com.protect7.authanalyzer.gui.main.ImportPanel_littlespidy;
import com.protect7.authanalyzer.gui.util.ImportRequestTableModel_littlespidy;
import com.protect7.authanalyzer.persistence.SessionStartupDialog_littlespidy;
import com.protect7.authanalyzer.persistence.SessionStateDTO_littlespidy;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.Globals;
import com.protect7.authanalyzer.util.XMLImportHelper_littlespidy;
import com.google.gson.Gson;

public class AuthAnalyzerTest_littlespidy {

	@Test
	public void testExtensionNameAndVersion() {
		assertEquals("ng-auth-analyzer_littlespidy", Globals.EXTENSION_NAME);
		assertNotNull(Globals.VERSION);
	}

	@Test
	public void testXMLImportParsingWithMultipleUsers() throws Exception {
		String xmlContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
				"<Content>\n" +
				"  <Message>\n" +
				"    <ID>1</ID>\n" +
				"    <Method>GET</Method>\n" +
				"    <Host>api.example.com</Host>\n" +
				"    <Path>/api/v1/profile</Path>\n" +
				"    <Comment>Profile query</Comment>\n" +
				"    <Original_Status_Code>200</Original_Status_Code>\n" +
				"    <Original_Length>150</Original_Length>\n" +
				"    <Original_Request><![CDATA[GET /api/v1/profile HTTP/1.1\nHost: api.example.com]]></Original_Request>\n" +
				"    <Original_Response><![CDATA[HTTP/1.1 200 OK\nContent-Length: 150\n\n{\"status\":\"ok\"}]]></Original_Response>\n" +
				"    <User_1_Bypass_Status>SAME</User_1_Bypass_Status>\n" +
				"    <User_1_Status_Code>200</User_1_Status_Code>\n" +
				"    <User_1_Length>150</User_1_Length>\n" +
				"    <User_1_Request><![CDATA[GET /api/v1/profile HTTP/1.1\nHost: api.example.com\nCookie: session=user1]]></User_1_Request>\n" +
				"    <User_1_Response><![CDATA[HTTP/1.1 200 OK\n\n{\"status\":\"ok\"}]]></User_1_Response>\n" +
				"    <User_2_Bypass_Status>DIFFERENT</User_2_Bypass_Status>\n" +
				"    <User_2_Status_Code>403</User_2_Status_Code>\n" +
				"    <User_2_Length>45</User_2_Length>\n" +
				"    <User_2_Request><![CDATA[GET /api/v1/profile HTTP/1.1\nHost: api.example.com\nCookie: session=user2]]></User_2_Request>\n" +
				"    <User_2_Response><![CDATA[HTTP/1.1 403 Forbidden\n\n{\"error\":\"denied\"}]]></User_2_Response>\n" +
				"    <User_3_Bypass_Status>SIMILAR</User_3_Bypass_Status>\n" +
				"    <User_3_Status_Code>200</User_3_Status_Code>\n" +
				"    <User_3_Length>130</User_3_Length>\n" +
				"    <User_3_Request><![CDATA[GET /api/v1/profile HTTP/1.1\nHost: api.example.com\nCookie: session=user3]]></User_3_Request>\n" +
				"    <User_3_Response><![CDATA[HTTP/1.1 200 OK\n\n{\"status\":\"partial\"}]]></User_3_Response>\n" +
				"  </Message>\n" +
				"</Content>";

		File tempXml = File.createTempFile("authanalyzer_test_import", ".xml");
		tempXml.deleteOnExit();
		Files.writeString(tempXml.toPath(), xmlContent, StandardCharsets.UTF_8);

		XMLImportHelper_littlespidy.ParseResult result = XMLImportHelper_littlespidy.parseXML(tempXml);

		assertEquals(1, result.originals.size());
		assertEquals(3, result.sessions.size());

		OriginalRequestResponse orig = result.originals.get(0);
		assertEquals(1, orig.getId());
		assertEquals("GET", orig.getMethod());
		assertEquals("api.example.com", orig.getHost());
		assertEquals("/api/v1/profile", orig.getUrl());
		assertEquals(200, orig.getStatusCode());
		assertEquals(150, orig.getResponseContentLength());
		assertEquals("Profile query", orig.getComment());

		Session user1 = result.sessions.get(0);
		assertEquals("User 1", user1.getName());
		AnalyzerRequestResponse u1Resp = user1.getRequestResponseMap().get(1);
		assertNotNull(u1Resp);
		assertEquals(BypassConstants.SAME, u1Resp.getStatus());
		assertEquals(200, u1Resp.getStatusCode());
		assertEquals(150, u1Resp.getResponseContentLength());

		Session user2 = result.sessions.get(1);
		assertEquals("User 2", user2.getName());
		AnalyzerRequestResponse u2Resp = user2.getRequestResponseMap().get(1);
		assertNotNull(u2Resp);
		assertEquals(BypassConstants.DIFFERENT, u2Resp.getStatus());
		assertEquals(403, u2Resp.getStatusCode());

		Session user3 = result.sessions.get(2);
		assertEquals("User 3", user3.getName());
		AnalyzerRequestResponse u3Resp = user3.getRequestResponseMap().get(1);
		assertNotNull(u3Resp);
		assertEquals(BypassConstants.SIMILAR, u3Resp.getStatus());
	}

	@Test
	public void testImportRequestTableModel() {
		ImportRequestTableModel_littlespidy model = new ImportRequestTableModel_littlespidy();
		assertEquals(0, model.getRowCount());

		CustomHttpService_littlespidy service = new CustomHttpService_littlespidy("example.com", 443, "https");
		CustomHttpRequestResponse_littlespidy reqResp = new CustomHttpRequestResponse_littlespidy(
				"GET /test HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8),
				"HTTP/1.1 200 OK\r\n\r\nhello".getBytes(StandardCharsets.UTF_8),
				service
		);
		OriginalRequestResponse orig = new OriginalRequestResponse(10, reqResp, "GET", "/test", "", 200, 5);

		Session s1 = new Session("User 1");
		AnalyzerRequestResponse arr1 = new AnalyzerRequestResponse(reqResp, BypassConstants.SAME, "", 200, 5);
		s1.getRequestResponseMap().put(10, arr1);

		List<OriginalRequestResponse> originals = new ArrayList<>();
		originals.add(orig);
		List<Session> sessions = new ArrayList<>();
		sessions.add(s1);

		model.setImportedData(originals, sessions);

		assertEquals(1, model.getRowCount());
		// 7 static columns + (1 session * 4 columns) = 11 columns
		assertEquals(11, model.getColumnCount());
		assertEquals(10, model.getValueAt(0, 0));
		assertEquals("GET", model.getValueAt(0, 1));
		assertEquals("example.com", model.getValueAt(0, 2));
		assertEquals("/test", model.getValueAt(0, 3));
		assertEquals(200, model.getValueAt(0, 4));

		assertEquals(orig, model.getOriginalRequestResponse(0));
		assertEquals(orig, model.getOriginalRequestResponseById(10));
	}

	@Test
	public void testSessionStateDTOSerialization() {
		SessionStateDTO_littlespidy dto = new SessionStateDTO_littlespidy();
		dto.version = "1.1.14";
		dto.timestamp = System.currentTimeMillis();
		dto.configSetupJson = "{\"sessions\":[]}";

		SessionStateDTO_littlespidy.MessageEntryDTO msg = new SessionStateDTO_littlespidy.MessageEntryDTO();
		msg.id = 1;
		msg.method = "POST";
		msg.host = "test.local";
		msg.url = "/api/login";
		msg.statusCode = 200;
		msg.responseContentLength = 100;
		msg.requestBase64 = "UE9TVCAvYXBpL2xvZ2lu";
		msg.responseBase64 = "SFRUUC8xLjEgMjAwIE9L";

		SessionStateDTO_littlespidy.SessionMessageDTO sMsg = new SessionStateDTO_littlespidy.SessionMessageDTO();
		sMsg.status = "SAME";
		sMsg.statusCode = 200;
		sMsg.responseContentLength = 100;
		msg.sessionData.put("User 1", sMsg);

		dto.liveMessages.add(msg);

		Gson gson = new Gson();
		String json = gson.toJson(dto);
		assertNotNull(json);

		SessionStateDTO_littlespidy deserialized = gson.fromJson(json, SessionStateDTO_littlespidy.class);
		assertEquals("1.1.14", deserialized.version);
		assertEquals(1, deserialized.liveMessages.size());
		assertEquals("POST", deserialized.liveMessages.get(0).method);
		assertEquals("User 1", deserialized.liveMessages.get(0).sessionData.keySet().iterator().next());
	}

	@Test
	public void testStartupDialogDefaults() {
		SessionStartupDialog_littlespidy.StartupResult res = SessionStartupDialog_littlespidy.promptUser(null, null, null);
		assertNotNull(res);
		assertEquals(SessionStartupDialog_littlespidy.StartupAction.TEMPORARY, res.getAction());
		assertNull(res.getSessionFile());
	}

	@Test
	public void testImportPanelInitializationWithoutNullTableModel() {
		ImportPanel_littlespidy panel = new ImportPanel_littlespidy(null);
		assertNotNull(panel.getImportTableModel());
		assertNotNull(panel.getTable().getModel());
		assertEquals(panel.getImportTableModel(), panel.getTable().getModel());
	}

	@Test
	public void testHistoryPanelInitialization() {
		HistoryPanel_littlespidy panel = new HistoryPanel_littlespidy(null);
		assertNotNull(panel.getTable().getModel());
		assertEquals(panel.getTableModel(), panel.getTable().getModel());
	}
}
