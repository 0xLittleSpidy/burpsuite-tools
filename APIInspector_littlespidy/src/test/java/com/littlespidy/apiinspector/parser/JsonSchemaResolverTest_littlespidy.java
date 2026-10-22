// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.parser;

import com.google.gson.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class JsonSchemaResolverTest_littlespidy {

    @Test
    @DisplayName("Resolve internal $ref pointer correctly")
    public void testResolveRef() {
        String json = """
        {
          "components": {
            "schemas": {
              "User": {
                "type": "object",
                "properties": {
                  "id": { "type": "integer" },
                  "username": { "type": "string" }
                }
              }
            }
          }
        }
        """;

        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        JsonObject resolved = JsonSchemaResolver_littlespidy.resolveRef(root, "#/components/schemas/User");

        assertNotNull(resolved);
        assertTrue(resolved.has("properties"));
        assertEquals("object", resolved.get("type").getAsString());
    }

    @Test
    @DisplayName("Generate sample from schema referencing definition with primitive format hints")
    public void testGenerateSampleFromSchemaRef() {
        String json = """
        {
          "components": {
            "schemas": {
              "Profile": {
                "type": "object",
                "properties": {
                  "email": { "type": "string", "format": "email" },
                  "active": { "type": "boolean", "default": true },
                  "age": { "type": "integer", "example": 25 }
                }
              }
            }
          }
        }
        """;

        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        JsonObject schemaWithRef = new JsonObject();
        schemaWithRef.addProperty("$ref", "#/components/schemas/Profile");

        Map<String, String> bodyParams = new LinkedHashMap<>();
        JsonElement sample = JsonSchemaResolver_littlespidy.generateSample(root, schemaWithRef, bodyParams, new HashSet<>(), 0);

        assertNotNull(sample);
        assertTrue(sample.isJsonObject());
        JsonObject sampleObj = sample.getAsJsonObject();

        assertEquals("user@example.com", sampleObj.get("email").getAsString());
        assertEquals("25", sampleObj.get("age").getAsString());
        assertTrue(sampleObj.get("active").getAsBoolean());

        assertTrue(bodyParams.containsKey("email"));
        assertTrue(bodyParams.containsKey("age"));
        assertTrue(bodyParams.containsKey("active"));
    }

    @Test
    @DisplayName("Handle circular schema references without infinite recursion")
    public void testCircularReferenceProtection() {
        String json = """
        {
          "components": {
            "schemas": {
              "Node": {
                "type": "object",
                "properties": {
                  "value": { "type": "string" },
                  "next": { "$ref": "#/components/schemas/Node" }
                }
              }
            }
          }
        }
        """;

        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        JsonObject schemaWithRef = new JsonObject();
        schemaWithRef.addProperty("$ref", "#/components/schemas/Node");

        Map<String, String> bodyParams = new LinkedHashMap<>();
        JsonElement sample = JsonSchemaResolver_littlespidy.generateSample(root, schemaWithRef, bodyParams, new HashSet<>(), 0);

        assertNotNull(sample);
        assertTrue(sample.isJsonObject());
        assertTrue(sample.getAsJsonObject().has("value"));
    }

    @Test
    @DisplayName("Generate sample from allOf composite schema")
    public void testAllOfComposition() {
        String json = """
        {
          "components": {
            "schemas": {
              "BaseEntity": {
                "type": "object",
                "properties": {
                  "id": { "type": "integer" }
                }
              },
              "DetailedEntity": {
                "allOf": [
                  { "$ref": "#/components/schemas/BaseEntity" },
                  {
                    "type": "object",
                    "properties": {
                      "details": { "type": "string" }
                    }
                  }
                ]
              }
            }
          }
        }
        """;

        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        JsonObject detailedRef = new JsonObject();
        detailedRef.addProperty("$ref", "#/components/schemas/DetailedEntity");

        Map<String, String> bodyParams = new LinkedHashMap<>();
        JsonElement sample = JsonSchemaResolver_littlespidy.generateSample(root, detailedRef, bodyParams, new HashSet<>(), 0);

        assertNotNull(sample);
        assertTrue(sample.isJsonObject());
        JsonObject sampleObj = sample.getAsJsonObject();

        assertTrue(sampleObj.has("id"));
        assertTrue(sampleObj.has("details"));
        assertTrue(bodyParams.containsKey("id"));
        assertTrue(bodyParams.containsKey("details"));
    }
}
