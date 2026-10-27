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
    @DisplayName("Parse OpenAPI 3.0 specification with $ref schema and requestBody resolution")
    public void testOpenApiWithRefBodyParsing() {
        String json = """
        {
          "openapi": "3.0.0",
          "info": { "title": "Petstore API", "version": "1.0.0" },
          "paths": {
            "/pets": {
              "post": {
                "summary": "Create Pet",
                "requestBody": {
                  "required": true,
                  "content": {
                    "application/json": {
                      "schema": {
                        "$ref": "#/components/schemas/NewPet"
                      }
                    }
                  }
                }
              }
            }
          },
          "components": {
            "schemas": {
              "NewPet": {
                "type": "object",
                "properties": {
                  "name": { "type": "string", "example": "Fluffy" },
                  "tag": { "type": "string" },
                  "age": { "type": "integer", "example": 3 }
                }
              }
            }
          }
        }
        """;

        ParseResult_littlespidy result = APIParserFactory_littlespidy.parse(json, "petstore.json", "FILE");
        assertTrue(result.isSuccess());
        ImportedCollection_littlespidy col = result.getCollection();
        assertNotNull(col);
        assertEquals(1, col.getEndpointCount());

        DiscoveredEndpoint_littlespidy petEp = col.getEndpoints().get(0);
        assertEquals("POST", petEp.getMethod());
        assertEquals("/pets", petEp.getPath());

        // Ensure body is not empty JSON "{}"
        assertNotNull(petEp.getRequestBodySample());
        assertFalse("{}".equals(petEp.getRequestBodySample().trim()), "Body sample must not be empty JSON");
        assertTrue(petEp.getRequestBodySample().contains("Fluffy"));
        assertTrue(petEp.getRequestBodySample().contains("age"));

        // Ensure body parameters are extracted
        assertNotNull(petEp.getBodyParams());
        assertFalse(petEp.getBodyParams().isEmpty(), "Body parameters must be extracted");
        assertTrue(petEp.getBodyParams().containsKey("name"));
        assertTrue(petEp.getBodyParams().containsKey("tag"));
        assertTrue(petEp.getBodyParams().containsKey("age"));
        assertEquals("Fluffy", petEp.getBodyParams().get("name"));
        assertTrue(petEp.getParametersSummary().contains("Body: ["));
    }

    @Test
    @DisplayName("Parse Swagger 2.0 with $ref body and formData parameters")
    public void testSwaggerWithRefAndFormDataParsing() {
        String json = """
        {
          "swagger": "2.0",
          "info": { "title": "Store Swagger API", "version": "1.0.0" },
          "paths": {
            "/orders": {
              "post": {
                "summary": "Create Order",
                "parameters": [
                  {
                    "name": "body",
                    "in": "body",
                    "schema": {
                      "$ref": "#/definitions/Order"
                    }
                  }
                ]
              }
            },
            "/upload": {
              "post": {
                "summary": "Upload File",
                "consumes": ["application/x-www-form-urlencoded"],
                "parameters": [
                  { "name": "fileDescription", "in": "formData", "type": "string" },
                  { "name": "category", "in": "formData", "type": "string", "default": "documents" }
                ]
              }
            }
          },
          "definitions": {
            "Order": {
              "type": "object",
              "properties": {
                "orderId": { "type": "integer", "example": 999 },
                "itemSku": { "type": "string", "example": "SKU-100" }
              }
            }
          }
        }
        """;

        ParseResult_littlespidy result = APIParserFactory_littlespidy.parse(json, "swagger_store.json", "FILE");
        assertTrue(result.isSuccess());
        ImportedCollection_littlespidy col = result.getCollection();
        assertNotNull(col);
        assertEquals(2, col.getEndpointCount());

        DiscoveredEndpoint_littlespidy orderEp = col.getEndpoints().stream()
                .filter(e -> "/orders".equals(e.getPath()))
                .findFirst().orElse(null);
        assertNotNull(orderEp);
        assertFalse("{}".equals(orderEp.getRequestBodySample().trim()));
        assertTrue(orderEp.getRequestBodySample().contains("999"));
        assertTrue(orderEp.getBodyParams().containsKey("orderId"));
        assertTrue(orderEp.getBodyParams().containsKey("itemSku"));

        DiscoveredEndpoint_littlespidy uploadEp = col.getEndpoints().stream()
                .filter(e -> "/upload".equals(e.getPath()))
                .findFirst().orElse(null);
        assertNotNull(uploadEp);
        assertTrue(uploadEp.getBodyParams().containsKey("fileDescription"));
        assertTrue(uploadEp.getBodyParams().containsKey("category"));
        assertTrue(uploadEp.getRequestBodySample().contains("fileDescription="));
        assertTrue(uploadEp.getRequestBodySample().contains("category=documents"));
    }

    @Test
    @DisplayName("Parse Postman collection with urlencoded body")
    public void testPostmanUrlEncodedBodyParsing() {
        String json = """
        {
          "info": {
            "name": "Form Postman Collection",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
          },
          "item": [
            {
              "name": "Token Request",
              "request": {
                "method": "POST",
                "url": { "raw": "https://auth.example.com/oauth/token" },
                "body": {
                  "mode": "urlencoded",
                  "urlencoded": [
                    { "key": "grant_type", "value": "password" },
                    { "key": "client_id", "value": "app123" }
                  ]
                }
              }
            }
          ]
        }
        """;

        ParseResult_littlespidy result = APIParserFactory_littlespidy.parse(json, "postman_form.json", "FILE");
        assertTrue(result.isSuccess());
        ImportedCollection_littlespidy col = result.getCollection();
        DiscoveredEndpoint_littlespidy ep = col.getEndpoints().get(0);

        assertTrue(ep.getBodyParams().containsKey("grant_type"));
        assertTrue(ep.getBodyParams().containsKey("client_id"));
        assertTrue(ep.getRequestBodySample().contains("grant_type=password"));
        assertTrue(ep.getRequestBodySample().contains("client_id=app123"));
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

    @Test
    @DisplayName("Parse tags and tag descriptions from Swagger 2.0 and OpenAPI 3.0 specs")
    public void testSwaggerAndOpenApiTagAndDescriptionParsing() {
        String swaggerJson = """
        {
          "swagger": "2.0",
          "info": { "title": "Petstore API", "version": "1.0.0" },
          "tags": [
            { "name": "pet", "description": "Operations about pets" },
            { "name": "store", "description": "Access to petstore orders" }
          ],
          "paths": {
            "/pet/{petId}": {
              "get": {
                "tags": ["pet"],
                "summary": "Find pet by ID"
              }
            },
            "/store/order": {
              "post": {
                "tags": ["store"],
                "summary": "Place an order"
              }
            }
          }
        }
        """;
        ParseResult_littlespidy swResult = APIParserFactory_littlespidy.parse(swaggerJson, "petstore.json", "FILE");
        assertTrue(swResult.isSuccess());
        ImportedCollection_littlespidy swCol = swResult.getCollection();
        assertEquals("Operations about pets", swCol.getTagDescriptions().get("pet"));
        assertEquals("Access to petstore orders", swCol.getTagDescriptions().get("store"));
        assertEquals("pet", swCol.getEndpoints().get(0).getTag());
        assertEquals("store", swCol.getEndpoints().get(1).getTag());

        String openApiJson = """
        {
          "openapi": "3.0.0",
          "info": { "title": "Inventory API", "version": "1.0" },
          "tags": [
            { "name": "inventory", "description": "Inventory management endpoints" }
          ],
          "paths": {
            "/inventory/items": {
              "get": {
                "tags": ["inventory"],
                "summary": "List items"
              }
            }
          }
        }
        """;
        ParseResult_littlespidy oasResult = APIParserFactory_littlespidy.parse(openApiJson, "inventory.json", "FILE");
        assertTrue(oasResult.isSuccess());
        ImportedCollection_littlespidy oasCol = oasResult.getCollection();
        assertEquals("Inventory management endpoints", oasCol.getTagDescriptions().get("inventory"));
        assertEquals("inventory", oasCol.getEndpoints().get(0).getTag());
    }
}
