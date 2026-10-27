// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.service;

import com.littlespidy.quickhelper.model.JsonTableData_littlespidy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonTableServiceTest_littlespidy {

    private JsonTableService_littlespidy service;

    @BeforeEach
    void setUp() {
        service = new JsonTableService_littlespidy();
    }

    @Test
    void testIsJsonCandidate() {
        assertTrue(service.isJsonCandidate("{\"id\": 1}", null));
        assertTrue(service.isJsonCandidate("[1, 2, 3]", null));
        assertTrue(service.isJsonCandidate("raw string", "application/json"));
        assertTrue(service.isJsonCandidate("raw string", "application/problem+json; charset=utf-8"));
        assertFalse(service.isJsonCandidate("<html></html>", "text/html"));
        assertFalse(service.isJsonCandidate(null, null));
    }

    @Test
    void testParseRootJsonArrayOfObjects() {
        String json = "[{\"id\": 101, \"username\": \"admin\", \"role\": \"SuperAdmin\"}, " +
                      "{\"id\": 102, \"username\": \"operator\", \"email\": \"ops@test.local\"}]";

        JsonTableData_littlespidy data = service.parseJsonToTable(json);

        assertNotNull(data);
        assertTrue(data.isArray());
        assertEquals(2, data.getRowCount());
        // Columns should unite keys: id, username, role, email
        assertTrue(data.getColumnNames().contains("id"));
        assertTrue(data.getColumnNames().contains("username"));
        assertTrue(data.getColumnNames().contains("role"));
        assertTrue(data.getColumnNames().contains("email"));

        List<List<String>> rows = data.getRowValues();
        assertEquals("101", rows.get(0).get(data.getColumnNames().indexOf("id")));
        assertEquals("admin", rows.get(0).get(data.getColumnNames().indexOf("username")));
        assertEquals("SuperAdmin", rows.get(0).get(data.getColumnNames().indexOf("role")));
        assertEquals("", rows.get(0).get(data.getColumnNames().indexOf("email")));

        assertEquals("102", rows.get(1).get(data.getColumnNames().indexOf("id")));
        assertEquals("ops@test.local", rows.get(1).get(data.getColumnNames().indexOf("email")));
    }

    @Test
    void testParseJsonObjectWithDataArray() {
        String json = "{\"status\": 200, \"data\": [{\"item_id\": \"A1\", \"price\": 19.99}, {\"item_id\": \"B2\", \"price\": 29.99}]}";

        JsonTableData_littlespidy data = service.parseJsonToTable(json);

        assertNotNull(data);
        assertTrue(data.isArray());
        assertEquals(2, data.getRowCount());
        assertEquals(List.of("item_id", "price"), data.getColumnNames());
        assertEquals("A1", data.getRowValues().get(0).get(0));
        assertEquals("19.99", data.getRowValues().get(0).get(1));
    }

    @Test
    void testParseFlattenedJsonObject() {
        String json = "{\"user\": {\"id\": 99, \"profile\": {\"first_name\": \"John\", \"active\": true}}, \"version\": 2}";

        JsonTableData_littlespidy data = service.parseJsonToTable(json);

        assertNotNull(data);
        assertFalse(data.isArray());
        assertEquals(List.of("Key / JSON Path", "Value"), data.getColumnNames());
        assertEquals(4, data.getRowCount());

        List<List<String>> rows = data.getRowValues();
        assertEquals("user.id", rows.get(0).get(0));
        assertEquals("99", rows.get(0).get(1));

        assertEquals("user.profile.first_name", rows.get(1).get(0));
        assertEquals("John", rows.get(1).get(1));

        assertEquals("user.profile.active", rows.get(2).get(0));
        assertEquals("true", rows.get(2).get(1));

        assertEquals("version", rows.get(3).get(0));
        assertEquals("2", rows.get(3).get(1));
    }

    @Test
    void testEmptyAndInvalidJson() {
        JsonTableData_littlespidy emptyData = service.parseJsonToTable("");
        assertEquals(0, emptyData.getRowCount());

        JsonTableData_littlespidy invalidData = service.parseJsonToTable("{not: json");
        assertEquals(0, invalidData.getRowCount());
    }

    @Test
    void testCsvExport() {
        List<String> cols = List.of("Name", "Role", "Note");
        List<List<String>> rows = List.of(
                List.of("Alice", "Admin", "Has \"super\" powers"),
                List.of("Bob", "Viewer", "Read,only")
        );

        String csv = service.toCsv(cols, rows);
        assertTrue(csv.contains("\"Name\",\"Role\",\"Note\""));
        assertTrue(csv.contains("\"Alice\",\"Admin\",\"Has \"\"super\"\" powers\""));
        assertTrue(csv.contains("\"Bob\",\"Viewer\",\"Read,only\""));
    }
}
