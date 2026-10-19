// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.parser;

import com.littlespidy.apiinspector.model.DiscoveredEndpoint_littlespidy;
import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class APIParserTest_littlespidy {

    @Test
    @DisplayName("Parse OpenAPI 3.0 JSON specification")
    public void testOpenApiJsonParsing() {
        String json = """
        {
          "openapi": "3.0.1",
          "info": {
            "title": "User Service API",
            "version": "1.0.0"
          },
          "servers": [
            { "url": "https://api.example.com/v1" }
          ],
          "paths": {
            "/users/{userId}": {
              "get": {
                "summary": "Get user by ID",
                "parameters": [
                  { "name": "userId", "in": "path", "required": true, "schema": { "type": "integer" } },
                  { "name": "includeDetails", "in": "query", "schema": { "type": "boolean" } }
                ],
                "security": [ { "BearerAuth": [] } ]
              },
              "delete": {
                "summary": "Delete user",
                "security": [ { "BearerAuth": [] } ]
              }
            },
            "/users": {
              "post": {
                "summary": "Create new user",
                "requestBody": {
                  "content": {
                    "application/json": {
                      "schema": {
                        "properties": {
                          "username": { "type": "string" },
                          "role": { "type": "string" }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """;

        ParseResult_littlespidy result = APIParserFactory_littlespidy.parse(json, "openapi_test.json", "FILE");
        assertTrue(result.isSuccess(), "Parsing should succeed");
        ImportedCollection_littlespidy col = result.getCollection();
        assertNotNull(col);
        assertEquals("User Service API", col.getName());
        assertEquals("OpenAPI 3.0.1", col.getFormatType());
        assertEquals("https://api.example.com/v1", col.getTargetBaseUrl());
        assertEquals(3, col.getEndpointCount());

        DiscoveredEndpoint_littlespidy getEp = col.getEndpoints().stream()
                .filter(e -> "GET".equals(e.getMethod()))
                .findFirst().orElse(null);
        assertNotNull(getEp);
        assertEquals("/users/{userId}", getEp.getPath());
        assertEquals("Get user by ID", getEp.getSummary());
        assertTrue(getEp.isRequiresAuth());
        assertTrue(getEp.getPathParams().containsKey("userId"));
        assertTrue(getEp.getQueryParams().containsKey("includeDetails"));

        DiscoveredEndpoint_littlespidy postEp = col.getEndpoints().stream()
                .filter(e -> "POST".equals(e.getMethod()))
                .findFirst().orElse(null);
        assertNotNull(postEp);
        assertNotNull(postEp.getRequestBodySample());
        assertTrue(postEp.getRequestBodySample().contains("username"));
    }

    @Test
    @DisplayName("Parse OpenAPI 3.0 YAML specification")
    public void testOpenApiYamlParsing() {
        String yaml = """
        openapi: 3.0.0
        info:
          title: Payment Gateway API
          version: 2.1.0
        servers:
          - url: https://payments.example.com
        paths:
          /charges:
            post:
              summary: Process charge
              security:
                - ApiKeyAuth: []
          /refunds:
            get:
              summary: List refunds
        """;

        ParseResult_littlespidy result = APIParserFactory_littlespidy.parse(yaml, "payments.yaml", "FILE");
        assertTrue(result.isSuccess());
        ImportedCollection_littlespidy col = result.getCollection();
        assertNotNull(col);
        assertEquals("Payment Gateway API", col.getName());
        assertEquals("https://payments.example.com", col.getTargetBaseUrl());
        assertEquals(2, col.getEndpointCount());
    }

    @Test
    @DisplayName("Parse Swagger 2.0 JSON specification")
    public void testSwaggerJsonParsing() {
        String json = """
        {
          "swagger": "2.0",
          "info": {
            "title": "Legacy Inventory API",
            "version": "1.0"
          },
          "host": "inventory.example.com",
          "basePath": "/api/v2",
          "schemes": ["https"],
          "paths": {
            "/items": {
              "get": {
                "summary": "List inventory items"
              }
            }
          }
        }
        """;

        ParseResult_littlespidy result = APIParserFactory_littlespidy.parse(json, "swagger.json", "FILE");
        assertTrue(result.isSuccess());
        ImportedCollection_littlespidy col = result.getCollection();
        assertNotNull(col);
        assertEquals("Legacy Inventory API", col.getName());
        assertEquals("Swagger 2.0", col.getFormatType());
        assertEquals("https://inventory.example.com/api/v2", col.getTargetBaseUrl());
        assertEquals(1, col.getEndpointCount());
        assertEquals("/items", col.getEndpoints().get(0).getPath());
    }

    @Test
    @DisplayName("Parse Swagger 2.0 YAML specification")
    public void testSwaggerYamlParsing() {
        String yaml = """
        swagger: "2.0"
        info:
          title: Inventory YAML API
          version: "2.0"
        host: yaml.example.com
        basePath: /v1
        schemes:
          - https
        paths:
          /catalog:
            get:
              summary: Catalog query
        """;

        ParseResult_littlespidy result = APIParserFactory_littlespidy.parse(yaml, "swagger.yaml", "FILE");
        assertTrue(result.isSuccess());
        ImportedCollection_littlespidy col = result.getCollection();
        assertEquals("Inventory YAML API", col.getName());
        assertEquals("https://yaml.example.com/v1", col.getTargetBaseUrl());
    }

    @Test
    @DisplayName("Parse Postman Collection v2.1")
    public void testPostmanCollectionParsing() {
        String json = """
        {
          "info": {
            "name": "E-Commerce Collection",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
          },
          "item": [
            {
              "name": "Auth",
              "item": [
                {
                  "name": "Login Request",
                  "request": {
                    "method": "POST",
                    "url": {
                      "raw": "https://auth.example.com/api/login",
                      "protocol": "https",
                      "host": ["auth", "example", "com"],
                      "path": ["api", "login"]
                    },
                    "header": [
                      { "key": "Content-Type", "value": "application/json" }
                    ],
                    "body": {
                      "mode": "raw",
                      "raw": "{\\"user\\":\\"admin\\",\\"pass\\":\\"secret\\"}"
                    }
                  }
                }
              ]
            },
            {
              "name": "Get Products",
              "request": {
                "method": "GET",
                "url": {
                  "raw": "https://api.example.com/v1/products?category=books",
                  "path": ["v1", "products"],
                  "query": [
                    { "key": "category", "value": "books" }
                  ]
                }
              }
            }
          ]
        }
        """;

        ParseResult_littlespidy result = APIParserFactory_littlespidy.parse(json, "ecommerce.postman_collection.json", "FILE");
        assertTrue(result.isSuccess());
        ImportedCollection_littlespidy col = result.getCollection();
        assertEquals("E-Commerce Collection", col.getName());
        assertTrue(col.getFormatType().contains("Postman"));
        assertEquals(2, col.getEndpointCount());

        DiscoveredEndpoint_littlespidy loginEp = col.getEndpoints().stream()
                .filter(e -> "POST".equals(e.getMethod()))
                .findFirst().orElse(null);
        assertNotNull(loginEp);
        assertEquals("/api/login", loginEp.getPath());
        assertTrue(loginEp.getRequestBodySample().contains("admin"));

        DiscoveredEndpoint_littlespidy prodEp = col.getEndpoints().stream()
                .filter(e -> "GET".equals(e.getMethod()))
                .findFirst().orElse(null);
        assertNotNull(prodEp);
        assertTrue(prodEp.getQueryParams().containsKey("category"));
    }

    @Test
    @DisplayName("Fail gracefully on invalid or unsupported format")
    public void testInvalidFormatHandling() {
        String randomText = "This is just a plain text file with no API schema.";
        ParseResult_littlespidy result = APIParserFactory_littlespidy.parse(randomText, "notes.txt", "FILE");
        assertFalse(result.isSuccess());
        assertNotNull(result.getErrorMessage());
        assertTrue(result.getErrorMessage().contains("Unsupported or invalid format"));
    }
}
