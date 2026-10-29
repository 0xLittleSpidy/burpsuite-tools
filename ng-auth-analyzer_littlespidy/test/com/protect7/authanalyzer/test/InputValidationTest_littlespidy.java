// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.test;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import com.google.gson.Gson;
import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;
import com.protect7.authanalyzer.entities.CustomHttpService_littlespidy;
import com.protect7.authanalyzer.inputvalidation.InputValidationConfig_littlespidy;
import com.protect7.authanalyzer.inputvalidation.InputValidationPayloadLoader_littlespidy;
import com.protect7.authanalyzer.inputvalidation.InputValidationPayload_littlespidy;
import com.protect7.authanalyzer.inputvalidation.InputValidationTableModel_littlespidy;
import com.protect7.authanalyzer.inputvalidation.InputValidationTestResult_littlespidy;
import com.protect7.authanalyzer.persistence.SessionStateDTO_littlespidy;

public class InputValidationTest_littlespidy {

    @Test
    public void testPayloadLoaderWithBigListOfNaughtyStrings() {
        List<InputValidationPayload_littlespidy> payloads = InputValidationPayloadLoader_littlespidy.loadAllPayloads();
        assertNotNull(payloads);
        assertTrue(payloads.size() >= 30, "Expected at least 30 payloads, found: " + payloads.size());

        // Check default essential probes exist
        long essentialCount = payloads.stream().filter(InputValidationPayload_littlespidy::isDefaultEssential).count();
        assertTrue(essentialCount > 0, "Expected default essential probes to be identified");

        // Verify that no payload category or name contains raw emojis to comply with Emoji Prohibition Rule
        for (InputValidationPayload_littlespidy p : payloads) {
            assertNotNull(p.getCategory());
            assertFalse(p.getCategory().equalsIgnoreCase("Emoji"), "Emoji category must be excluded");
        }
    }

    @Test
    public void testInputValidationConfigDefaultsAndReset() {
        InputValidationConfig_littlespidy config = new InputValidationConfig_littlespidy();
        assertTrue(config.isFuzzUrlParams());
        assertTrue(config.isFuzzBodyParams());
        assertTrue(config.isFuzzJsonParams());
        assertTrue(config.isFuzzXmlParams());
        assertTrue(config.isFuzzMultipartParams());
        assertFalse(config.isFuzzCookieParams());

        assertEquals(10, config.getMaxConcurrentThreads());
        assertEquals(0, config.getDelayBetweenRequestsMs());
        assertEquals(300, config.getSizeDiffPercent());
        assertNotNull(config.getErrorSignatures());
        assertTrue(config.getErrorSignatures().contains("syntax error"));

        // Test enable all and reset to default
        config.enableAllPayloads(true);
        assertTrue(config.getPayloads().stream().allMatch(InputValidationPayload_littlespidy::isEnabled));

        config.resetToDefaultEssential();
        for (InputValidationPayload_littlespidy p : config.getPayloads()) {
            assertEquals(p.isDefaultEssential(), p.isEnabled());
        }
    }

    @Test
    public void testTableModelAndResultCreation() {
        InputValidationTableModel_littlespidy model = new InputValidationTableModel_littlespidy();
        assertEquals(0, model.getRowCount());
        assertEquals(12, model.getColumnCount());

        CustomHttpService_littlespidy svc = new CustomHttpService_littlespidy("example.com", 443, "https");
        CustomHttpRequestResponse_littlespidy msg = new CustomHttpRequestResponse_littlespidy(
                "POST /search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test".getBytes(),
                "HTTP/1.1 500 Error\r\n\r\nSyntax error".getBytes(),
                svc
        );

        InputValidationTestResult_littlespidy res = new InputValidationTestResult_littlespidy(
                1, "SQL Injection", "POST", "example.com", "/search",
                "q", "URL", "Special Chars", "'\\\"><;|\\\\][}{`$",
                200, 500, 400, 1200, 200,
                "Error Signature (syntax error)", "Matched syntax error",
                msg, msg
        );

        model.addResult(res);
        assertEquals(1, model.getRowCount());
        assertEquals(1, model.getValueAt(0, 0));
        assertEquals("POST", model.getValueAt(0, 1));
        assertEquals("example.com", model.getValueAt(0, 2));
        assertEquals("/search", model.getValueAt(0, 3));
        assertEquals("SQL Injection", model.getValueAt(0, 4));
        assertEquals("q", model.getValueAt(0, 5));
        assertEquals("URL", model.getValueAt(0, 6));
        assertEquals(500, model.getValueAt(0, 8));
        assertEquals(1200, model.getValueAt(0, 9));
        assertEquals("+200%", model.getValueAt(0, 10));
        assertEquals("Error Signature (syntax error)", model.getValueAt(0, 11));

        InputValidationTestResult_littlespidy retrieved = model.getResult(0);
        assertNotNull(retrieved);
        assertEquals("Special Chars", retrieved.getPayloadName());

        model.clear();
        assertEquals(0, model.getRowCount());
    }

    @Test
    public void testSessionStateDTOSerialization() {
        SessionStateDTO_littlespidy dto = new SessionStateDTO_littlespidy();
        dto.version = "1.1.14";

        SessionStateDTO_littlespidy.InputValidationResultEntryDTO entry = new SessionStateDTO_littlespidy.InputValidationResultEntryDTO();
        entry.id = 1;
        entry.category = "Boundary";
        entry.method = "GET";
        entry.host = "api.corp.local";
        entry.path = "/data";
        entry.parameterName = "id";
        entry.parameterType = "URL";
        entry.payloadName = "Negative Integer";
        entry.payloadValue = "-1";
        entry.baseStatusCode = 200;
        entry.statusCode = 400;
        entry.anomalyType = "Status Shift (200 -> 400)";
        dto.inputValidationResults.add(entry);

        Gson gson = new Gson();
        String json = gson.toJson(dto);
        assertNotNull(json);

        SessionStateDTO_littlespidy deserialized = gson.fromJson(json, SessionStateDTO_littlespidy.class);
        assertNotNull(deserialized);
        assertEquals(1, deserialized.inputValidationResults.size());
        assertEquals("-1", deserialized.inputValidationResults.get(0).payloadValue);
        assertEquals("Status Shift (200 -> 400)", deserialized.inputValidationResults.get(0).anomalyType);
    }
}
