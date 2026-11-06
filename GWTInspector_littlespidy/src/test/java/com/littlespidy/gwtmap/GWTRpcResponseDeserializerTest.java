// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap;

import com.littlespidy.gwtmap.model.GWTRpcResponse;
import com.littlespidy.gwtmap.model.GwtProxyHistoryEntry;
import com.littlespidy.gwtmap.parser.GWTRpcResponseDeserializer;
import com.littlespidy.gwtmap.ui.GwtProxyHistoryTableModel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class GWTRpcResponseDeserializerTest {

    @Test
    public void testSuccessfulGwtResponse() {
        String payload = "//OK[3,2,[\"java.lang.String/2004016611\",\"Hello GWT World\"],0,7]";
        assertTrue(GWTRpcResponseDeserializer.isGwtResponse(payload));

        GWTRpcResponse resp = GWTRpcResponseDeserializer.deserialize(payload);
        assertNotNull(resp);
        assertTrue(resp.isSuccess());
        assertFalse(resp.isException());
        assertEquals(3, resp.getStreamVersion());
        assertEquals(2, resp.getFlags());
        assertEquals("java.lang.String", resp.getReturnType());
        assertEquals(2, resp.getStringTable().size());
        assertEquals(1, resp.getExtractedValues().size());
        assertEquals("Hello GWT World", resp.getExtractedValues().get(0));

        String summary = resp.getFormattedSummary();
        assertNotNull(summary);
        assertTrue(summary.contains("SUCCESS (//OK)"));
        assertTrue(summary.contains("Hello GWT World"));
        assertTrue(summary.contains("java.lang.String"));
    }

    @Test
    public void testExceptionGwtResponse() {
        String exPayload = "//EX[2,1,[\"com.google.gwt.user.client.rpc.SerializationException/2004016611\",\"Invalid character found in payload stream\"],0,7]";
        assertTrue(GWTRpcResponseDeserializer.isGwtResponse(exPayload));

        GWTRpcResponse resp = GWTRpcResponseDeserializer.deserialize(exPayload);
        assertNotNull(resp);
        assertFalse(resp.isSuccess());
        assertTrue(resp.isException());
        assertEquals("com.google.gwt.user.client.rpc.SerializationException", resp.getExceptionType());
        assertEquals("Invalid character found in payload stream", resp.getExceptionMessage());

        String summary = resp.getFormattedSummary();
        assertTrue(summary.contains("EXCEPTION (//EX)"));
        assertTrue(summary.contains("SerializationException"));
        assertTrue(summary.contains("Invalid character"));
    }

    @Test
    public void testMalformedPayloadGracefulHandling() {
        String malformed = "//OK[not a json array";
        assertTrue(GWTRpcResponseDeserializer.isGwtResponse(malformed));

        GWTRpcResponse resp = GWTRpcResponseDeserializer.deserialize(malformed);
        assertNotNull(resp);
        assertEquals(malformed, resp.getRawResponse());
        assertNotNull(resp.getFormattedSummary());
        assertTrue(resp.getFormattedSummary().contains("RAW FALLBACK"));
    }

    @Test
    public void testGwtProxyHistoryTableModel() {
        GwtProxyHistoryTableModel model = new GwtProxyHistoryTableModel();
        GwtProxyHistoryEntry entry = new GwtProxyHistoryEntry(
                1,
                "14:30:00",
                "POST",
                "authenticateUser",
                "AuthService",
                "https://example.com/app/authService",
                200,
                350,
                "text/x-gwt-rpc",
                45,
                true,
                null
        );

        model.addEntry(entry);
        assertEquals(1, model.getRowCount());
        assertEquals(10, model.getColumnCount());
        assertEquals(1, model.getValueAt(0, 0));
        assertEquals("14:30:00", model.getValueAt(0, 1));
        assertEquals("POST", model.getValueAt(0, 2));
        assertEquals("authenticateUser", model.getValueAt(0, 3));
        assertEquals("AuthService", model.getValueAt(0, 4));
        assertEquals("https://example.com/app/authService", model.getValueAt(0, 5));
        assertEquals(200, model.getValueAt(0, 6));
        assertEquals(350, model.getValueAt(0, 7));
        assertEquals("text/x-gwt-rpc", model.getValueAt(0, 8));
        assertEquals("45 ms", model.getValueAt(0, 9));
    }
}
