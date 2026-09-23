// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.persistence;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class SimpleJsonTest {

    @Test
    public void testSerializationAndParsingPrimitives() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("str", "Hello \"World\"\nLine2\tTabbed\\Escaped");
        map.put("int", 42);
        map.put("long", 1234567890123L);
        map.put("double", 3.14159);
        map.put("boolTrue", true);
        map.put("boolFalse", false);
        map.put("nullVal", null);

        String json = SimpleJson.serialize(map);
        assertNotNull(json);

        Object parsed = SimpleJson.parse(json);
        assertTrue(parsed instanceof Map);
        @SuppressWarnings("unchecked")
        Map<String, Object> parsedMap = (Map<String, Object>) parsed;

        assertEquals("Hello \"World\"\nLine2\tTabbed\\Escaped", SimpleJson.getString(parsedMap, "str", ""));
        assertEquals(42, SimpleJson.getInt(parsedMap, "int", 0));
        assertEquals(1234567890123L, SimpleJson.getLong(parsedMap, "long", 0L));
        assertEquals(3.14159, SimpleJson.getDouble(parsedMap, "double", 0.0), 0.0001);
        assertTrue(SimpleJson.getBoolean(parsedMap, "boolTrue", false));
        assertFalse(SimpleJson.getBoolean(parsedMap, "boolFalse", true));
        assertNull(parsedMap.get("nullVal"));
    }

    @Test
    public void testNestedStructures() {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("subKey", "subValue");
        inner.put("count", 100);

        List<Object> list = new ArrayList<>();
        list.add("item1");
        list.add(200);
        list.add(Map.of("deepKey", "deepVal"));

        root.put("nestedObj", inner);
        root.put("items", list);

        String json = SimpleJson.serialize(root);
        Object parsed = SimpleJson.parse(json);

        assertTrue(parsed instanceof Map);
        @SuppressWarnings("unchecked")
        Map<String, Object> parsedMap = (Map<String, Object>) parsed;

        Map<String, Object> parsedInner = SimpleJson.getMap(parsedMap, "nestedObj");
        assertEquals("subValue", SimpleJson.getString(parsedInner, "subKey", ""));
        assertEquals(100, SimpleJson.getInt(parsedInner, "count", 0));

        List<Object> parsedList = SimpleJson.getList(parsedMap, "items");
        assertEquals(3, parsedList.size());
        assertEquals("item1", parsedList.get(0));
        assertEquals(200, ((Number) parsedList.get(1)).intValue());
        assertTrue(parsedList.get(2) instanceof Map);
    }
}
