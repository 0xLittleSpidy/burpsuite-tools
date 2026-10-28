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
import com.protect7.authanalyzer.cors.CorsEngine_littlespidy;
import com.protect7.authanalyzer.cors.CorsTestResult_littlespidy;
import com.protect7.authanalyzer.cors.CorsTestResult_littlespidy.CorsSeverity;
import com.protect7.authanalyzer.gui.cors.CorsHistoryPanel_littlespidy;
import com.protect7.authanalyzer.gui.cors.CorsImportPanel_littlespidy;
import com.protect7.authanalyzer.gui.main.HistoryPanel_littlespidy;
import com.protect7.authanalyzer.gui.main.ImportPanel_littlespidy;
import com.protect7.authanalyzer.gui.util.DomainFilterDropDown_littlespidy;
import com.protect7.authanalyzer.gui.util.ImportRequestTableModel_littlespidy;
import com.protect7.authanalyzer.gui.util.MethodFilterDropDown_littlespidy;
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

		assertEquals("Original Status Code", model.getColumnName(4));
		assertEquals("User 1 Status Code", model.getColumnName(5));
		assertEquals("Original Length", model.getColumnName(6));
		assertEquals("User 1 Length", model.getColumnName(7));
		assertEquals("User 1 Diff", model.getColumnName(8));
		assertEquals("User 1 Status", model.getColumnName(9));
	}

	@Test
	public void testMethodFilterDropDown() {
		MethodFilterDropDown_littlespidy dropdown = new MethodFilterDropDown_littlespidy();
		assertEquals("Methods: All", dropdown.getText());
		assertTrue(dropdown.isMethodSelected("GET"));
		assertTrue(dropdown.isMethodSelected("POST"));

		dropdown.setMethodSelected("GET", false);
		assertFalse(dropdown.isMethodSelected("GET"));
		assertTrue(dropdown.isMethodSelected("POST"));

		dropdown.selectAll();
		assertEquals("Methods: All", dropdown.getText());
		assertTrue(dropdown.isMethodSelected("GET"));

		dropdown.selectNone();
		assertEquals("Methods: None", dropdown.getText());
		assertFalse(dropdown.isMethodSelected("GET"));
	}

	@Test
	public void testImportPanelSetImportedDataDoesNotThrowRowIndexOutOfRange() {
		ImportPanel_littlespidy panel = new ImportPanel_littlespidy(null);
		CustomHttpService_littlespidy service = new CustomHttpService_littlespidy("example.com", 443, "https");
		CustomHttpRequestResponse_littlespidy reqResp = new CustomHttpRequestResponse_littlespidy(
				"GET /test HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.UTF_8),
				"HTTP/1.1 200 OK\r\n\r\nhello".getBytes(StandardCharsets.UTF_8),
				service
		);
		OriginalRequestResponse orig = new OriginalRequestResponse(1, reqResp, "GET", "/test", "", 200, 5);
		Session s = new Session("User 1");
		s.getRequestResponseMap().put(1, new AnalyzerRequestResponse(reqResp, BypassConstants.SAME, "", 200, 5));

		List<OriginalRequestResponse> originals = new ArrayList<>();
		originals.add(orig);
		List<Session> sessions = new ArrayList<>();
		sessions.add(s);

		assertDoesNotThrow(() -> {
			panel.setImportedData(originals, sessions);
		});

		assertDoesNotThrow(() -> {
			panel.setImportedData(new ArrayList<>(), new ArrayList<>());
		});
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

	@Test
	public void testDomainFilterDropDown() {
		DomainFilterDropDown_littlespidy dropdown = new DomainFilterDropDown_littlespidy();
		assertEquals("Domains: All", dropdown.getText());
		assertTrue(dropdown.isDomainSelected("api.target.com"));

		dropdown.updateDomains(List.of("api.target.com", "auth.target.com"));
		assertEquals("Domains: All", dropdown.getText());
		assertTrue(dropdown.isDomainSelected("api.target.com"));
		assertTrue(dropdown.isDomainSelected("auth.target.com"));

		dropdown.setDomainSelected("api.target.com", false);
		assertFalse(dropdown.isDomainSelected("api.target.com"));
		assertTrue(dropdown.isDomainSelected("auth.target.com"));
	}

	@Test
	public void testCorsTestVectorsGeneration() {
		List<CorsEngine_littlespidy.TestVector> vectors = CorsEngine_littlespidy.generateTestVectors("example.com", "evil.com");
		assertEquals(29, vectors.size());

		boolean hasDotUnderscore = false;
		boolean hasNullOrigin = false;
		boolean hasTrustSubdomain = false;
		for (CorsEngine_littlespidy.TestVector v : vectors) {
			if ("dot_underscore_dot".equals(v.id)) hasDotUnderscore = true;
			if ("trusted_null".equals(v.id)) hasNullOrigin = true;
			if ("trust_subdomain".equals(v.id)) hasTrustSubdomain = true;
		}
		assertTrue(hasDotUnderscore, "Should have dot underscore dot vector");
		assertTrue(hasNullOrigin, "Should have trusted null origin vector");
		assertTrue(hasTrustSubdomain, "Should have trust subdomain vector");
	}

	@Test
	public void testCorsPanelsInitialization() {
		CorsHistoryPanel_littlespidy historyPanel = new CorsHistoryPanel_littlespidy(null);
		assertNotNull(historyPanel.getTable().getModel());
		assertEquals(0, historyPanel.getTableModel().getRowCount());
		assertNotNull(historyPanel.getViewerSplitPane());
		assertNotNull(historyPanel.getViewerSplitPane().getLeftComponent());
		assertNotNull(historyPanel.getViewerSplitPane().getRightComponent());
		assertEquals("evil.com", historyPanel.getAttackerUrl());

		CorsImportPanel_littlespidy importPanel = new CorsImportPanel_littlespidy(null);
		assertNotNull(importPanel.getTable().getModel());
		assertEquals(0, importPanel.getTableModel().getRowCount());
		assertNotNull(importPanel.getViewerSplitPane());
		assertNotNull(importPanel.getViewerSplitPane().getLeftComponent());
		assertNotNull(importPanel.getViewerSplitPane().getRightComponent());
	}

	@Test
	public void testSessionAttackerUrlAndCorsSettings() {
		Session session = new Session("TestSession");
		assertEquals("evil.com", session.getAttackerUrl());
		session.setAttackerUrl("custom-attacker.org");
		assertEquals("custom-attacker.org", session.getAttackerUrl());
		session.setTestCors(true);
		assertTrue(session.isTestCors());
	}

	@Test
	public void testConvertEngineExtractUrlEncodedParams() {
		String body = "user=admin&action=update&id=42";
		String query = com.protect7.authanalyzer.convert.ConvertEngine_littlespidy.extractBodyParametersAsQueryString(
				body, "application/x-www-form-urlencoded");
		assertEquals(body, query);
	}

	@Test
	public void testConvertEngineExtractJsonParams() {
		String body = "{\"role\":\"admin\",\"userId\":\"99\"}";
		String query = com.protect7.authanalyzer.convert.ConvertEngine_littlespidy.extractBodyParametersAsQueryString(
				body, "application/json");
		assertTrue(query.contains("role=admin"));
		assertTrue(query.contains("userId=99"));
	}

	@Test
	public void testConversionTableModelOperations() {
		com.protect7.authanalyzer.convert.ConversionTableModel_littlespidy model =
				new com.protect7.authanalyzer.convert.ConversionTableModel_littlespidy();
		assertEquals(0, model.getRowCount());

		com.protect7.authanalyzer.convert.ConversionResult_littlespidy r1 =
				new com.protect7.authanalyzer.convert.ConversionResult_littlespidy(
						1, "GET", "api.target.com", "/api/role?role=admin",
						403, 200, 45, 150, "application/json",
						"Auth Bypass Detected (POST 403 -> GET 200)", "High", "Evidence test",
						null, null);

		model.addResult(r1);
		assertEquals(1, model.getRowCount());
		assertEquals(8, model.getColumnCount());
		assertEquals(1, model.getValueAt(0, 0));
		assertEquals("api.target.com", model.getValueAt(0, 1));
		assertEquals("/api/role?role=admin", model.getValueAt(0, 2));
		assertEquals(403, model.getValueAt(0, 3));
		assertEquals(200, model.getValueAt(0, 4));
		assertEquals(45, model.getValueAt(0, 5));
		assertEquals(150, model.getValueAt(0, 6));
		assertEquals("Auth Bypass Detected (POST 403 -> GET 200)", model.getValueAt(0, 7));

		model.clear();
		assertEquals(0, model.getRowCount());
	}

	@Test
	public void testPortSwigger29CorsTechniquesGeneration() {
		List<CorsEngine_littlespidy.TestVector> vectors =
				CorsEngine_littlespidy.generateTestVectors("target.com", "attacker.com");
		assertEquals(29, vectors.size());

		// Verify key PortSwigger vectors are present
		boolean hasDotUnderscore = false;
		boolean hasSafariComma = false;
		boolean hasSafariSemicolon = false;
		boolean hasNullOrigin = false;
		boolean hasIpv6 = false;
		for (CorsEngine_littlespidy.TestVector v : vectors) {
			if ("dot_underscore_dot".equals(v.id)) hasDotUnderscore = true;
			if ("safari_comma".equals(v.id)) hasSafariComma = true;
			if ("safari_semicolon".equals(v.id)) hasSafariSemicolon = true;
			if ("trusted_null".equals(v.id)) hasNullOrigin = true;
			if ("ipv6_loopback".equals(v.id)) hasIpv6 = true;
		}
		assertTrue(hasDotUnderscore);
		assertTrue(hasSafariComma);
		assertTrue(hasSafariSemicolon);
		assertTrue(hasNullOrigin);
		assertTrue(hasIpv6);
	}

	@Test
	public void testExactPathFilter() {
		com.protect7.authanalyzer.filter.ExactPathFilter_littlespidy filter =
				new com.protect7.authanalyzer.filter.ExactPathFilter_littlespidy(0, "Exact match");
		filter.registerOnOffButton(new com.protect7.authanalyzer.gui.util.HintCheckBox("Exact match"));
		filter.setFilterStringLiterals(new String[] { "/api/v1/logout", "/healthz" });
		filter.setIsSelected(true);

		assertTrue(filter.hasStringLiterals());
		assertTrue(filter.isSelected());
		assertEquals(2, filter.getFilterStringLiterals().length);
	}

	@Test
	public void testCompleteUrlFilter() {
		com.protect7.authanalyzer.filter.CompleteUrlFilter_littlespidy filter =
				new com.protect7.authanalyzer.filter.CompleteUrlFilter_littlespidy(0, "Complete URL match");
		filter.registerOnOffButton(new com.protect7.authanalyzer.gui.util.HintCheckBox("Complete URL match"));
		filter.setFilterStringLiterals(new String[] { "https://example.com/api/ping" });
		filter.setIsSelected(true);

		assertTrue(filter.hasStringLiterals());
		assertTrue(filter.isSelected());
		assertEquals("https://example.com/api/ping", filter.getFilterStringLiterals()[0]);
	}

	@Test
	public void testConvertXMLHelperRoundtrip() throws Exception {
		List<com.protect7.authanalyzer.convert.ConversionResult_littlespidy> list = new ArrayList<>();
		com.protect7.authanalyzer.convert.ConversionResult_littlespidy res =
				new com.protect7.authanalyzer.convert.ConversionResult_littlespidy(
						1, "POST", "api.target.com", "/api/data",
						200, 200, 100, 100, "application/json", "Identical Response", "High", "evidence",
						null, null);
		list.add(res);

		File tempXml = File.createTempFile("convert_test_", ".xml");
		tempXml.deleteOnExit();

		boolean ok = com.protect7.authanalyzer.util.ConvertXMLHelper_littlespidy.exportToXML(tempXml, list);
		assertTrue(ok);
		assertTrue(tempXml.length() > 0);

		List<com.protect7.authanalyzer.convert.ConversionResult_littlespidy> imported =
				com.protect7.authanalyzer.util.ConvertXMLHelper_littlespidy.importFromXML(tempXml);
		assertEquals(1, imported.size());
		assertEquals(1, imported.get(0).getId());
		assertEquals("POST", imported.get(0).getMethod());
		assertEquals("api.target.com", imported.get(0).getHost());
		assertEquals("/api/data", imported.get(0).getPath());
		assertEquals("Identical Response", imported.get(0).getSignal());
	}

	@Test
	public void testConvertPostToGetPanelInitialization() {
		com.protect7.authanalyzer.gui.convert.ConvertPostToGetPanel_littlespidy panel =
				new com.protect7.authanalyzer.gui.convert.ConvertPostToGetPanel_littlespidy(null);
		assertNotNull(panel.getConversionTable());
		assertNotNull(panel.getConversionTableModel());
		assertEquals(panel.getConversionTableModel(), panel.getConversionTable().getModel());
	}

	@Test
	public void testConvertResultsSessionStateDTORoundtrip() {
		SessionStateDTO_littlespidy dto = new SessionStateDTO_littlespidy();
		dto.version = Globals.VERSION;

		SessionStateDTO_littlespidy.ConvertResultEntryDTO cr = new SessionStateDTO_littlespidy.ConvertResultEntryDTO();
		cr.id = 1;
		cr.method = "GET";
		cr.host = "api.target.com";
		cr.path = "/api/v1/update?admin=1";
		cr.postStatus = 403;
		cr.getStatus = 200;
		cr.postLength = 40;
		cr.getLength = 160;
		cr.contentType = "application/json";
		cr.signal = "Auth Bypass Detected (POST 403 -> GET 200)";
		cr.severity = "High";
		cr.evidence = "Test evidence";

		dto.convertResults.add(cr);

		Gson gson = new Gson();
		String json = gson.toJson(dto);
		assertNotNull(json);

		SessionStateDTO_littlespidy deserialized = gson.fromJson(json, SessionStateDTO_littlespidy.class);
		assertEquals(1, deserialized.convertResults.size());
		assertEquals("api.target.com", deserialized.convertResults.get(0).host);
		assertEquals(403, deserialized.convertResults.get(0).postStatus);
		assertEquals(200, deserialized.convertResults.get(0).getStatus);
		assertEquals("High", deserialized.convertResults.get(0).severity);
	}

	@Test
	public void testCorsTableModelOperations() {
		com.protect7.authanalyzer.cors.CorsTableModel_littlespidy model =
				new com.protect7.authanalyzer.cors.CorsTableModel_littlespidy();
		assertEquals(0, model.getRowCount());
		assertEquals(9, model.getColumnCount());

		com.protect7.authanalyzer.cors.CorsTestResult_littlespidy res =
				new com.protect7.authanalyzer.cors.CorsTestResult_littlespidy(
						1, "POST", "example.com", "/api/data", "https://evil.com",
						"Arbitrary Origin Reflection", "https://evil.com", true,
						200, 1024, com.protect7.authanalyzer.cors.CorsTestResult_littlespidy.CorsSeverity.HIGH, null);

		model.addResult(res);
		assertEquals(1, model.getRowCount());
		assertEquals(1, model.getValueAt(0, 0));
		assertEquals("example.com", model.getValueAt(0, 1));
		assertEquals("/api/data", model.getValueAt(0, 2));
		assertEquals("Arbitrary Origin Reflection", model.getValueAt(0, 3));
		assertEquals("https://evil.com", model.getValueAt(0, 4));
		assertEquals("https://evil.com", model.getValueAt(0, 5));
		assertEquals(true, model.getValueAt(0, 6));
		assertEquals(200, model.getValueAt(0, 7));
		assertEquals(1024, model.getValueAt(0, 8));

		model.clear();
		assertEquals(0, model.getRowCount());
	}

	@Test
	public void testAcaoFilterDropDown() {
		com.protect7.authanalyzer.gui.util.AcaoFilterDropDown_littlespidy dropdown =
				new com.protect7.authanalyzer.gui.util.AcaoFilterDropDown_littlespidy();
		assertTrue(dropdown.isAcaoSelected("*"));
		assertTrue(dropdown.isAcaoSelected(""));

		dropdown.updateAcaoValues(java.util.Arrays.asList("https://evil.com", "null", ""));
		assertTrue(dropdown.isAcaoSelected("https://evil.com"));
		assertTrue(dropdown.isAcaoSelected("null"));
		assertTrue(dropdown.isAcaoSelected(null));
		assertTrue(dropdown.isAcaoSelected(""));
	}

	@Test
	public void testSessionStatusFilterDropDown() {
		com.protect7.authanalyzer.gui.util.SessionStatusFilterDropDown_littlespidy dropdown =
				new com.protect7.authanalyzer.gui.util.SessionStatusFilterDropDown_littlespidy();

		java.util.Map<String, java.util.Set<Integer>> map = new java.util.HashMap<String, java.util.Set<Integer>>();
		map.put("admin", new java.util.HashSet<Integer>(java.util.Arrays.asList(200, 400)));
		map.put("user", new java.util.HashSet<Integer>(java.util.Arrays.asList(201, 403)));
		dropdown.updateSessionStatuses(map);

		// With all selected, all match
		assertTrue(dropdown.isRowMatching(1, null));
	}
}
