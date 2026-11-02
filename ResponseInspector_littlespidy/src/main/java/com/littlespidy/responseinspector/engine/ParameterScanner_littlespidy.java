// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.littlespidy.responseinspector.model.ParameterEntry_littlespidy;
import com.littlespidy.responseinspector.model.ParameterOccurrence_littlespidy;
import com.littlespidy.responseinspector.model.ParameterSource_littlespidy;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts and groups parameters from HTTP request and response bodies.
 * Supports JSON keys, form-urlencoded parameters, multipart form fields, and XML/HTML inputs.
 */
public class ParameterScanner_littlespidy {

    private static final Pattern FORM_PAIR_PATTERN = Pattern.compile("([^&=?#]+)=([^&#]*)");
    private static final Pattern MULTIPART_NAME_PATTERN = Pattern.compile("name=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_INPUT_PATTERN = Pattern.compile("<(?:input|textarea|select)[^>]*?\\bname=[\"']([^\"']+)[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern XML_TAG_PATTERN = Pattern.compile("<([a-zA-Z_][a-zA-Z0-9_.-]*)(?:\\s+[^>]*)?>");

    public void scanItem(HttpRequestResponse item, Map<String, ParameterEntry_littlespidy> parameterMap) {
        if (item == null) {
            return;
        }

        LocalDateTime now = LocalDateTime.now();
        String url = item.request() != null && item.request().url() != null ? item.request().url() : "";
        String method = item.request() != null && item.request().method() != null ? item.request().method() : "GET";
        short statusCode = item.response() != null ? item.response().statusCode() : 0;

        // 1. Scan Request Body
        if (item.request() != null) {
            HttpRequest req = item.request();
            String reqBody = req.bodyToString();
            if (reqBody != null && !reqBody.isBlank()) {
                String contentType = req.headerValue("Content-Type");
                if (contentType == null) {
                    contentType = "";
                }
                contentType = contentType.toLowerCase();

                if (contentType.contains("application/json") || isLikelyJson(reqBody)) {
                    extractJsonParameters(item, reqBody, ParameterSource_littlespidy.REQUEST_BODY, url, statusCode, method, now, parameterMap);
                } else if (contentType.contains("multipart/form-data")) {
                    extractMultipartParameters(item, reqBody, ParameterSource_littlespidy.REQUEST_BODY, url, statusCode, method, now, parameterMap);
                } else if (contentType.contains("application/x-www-form-urlencoded") || reqBody.contains("=")) {
                    extractFormUrlencodedParameters(item, reqBody, ParameterSource_littlespidy.REQUEST_BODY, url, statusCode, method, now, parameterMap);
                } else if (contentType.contains("xml") || reqBody.trim().startsWith("<")) {
                    extractXmlHtmlParameters(item, reqBody, ParameterSource_littlespidy.REQUEST_BODY, url, statusCode, method, now, parameterMap);
                }
            }
        }

        // 2. Scan Response Body
        if (item.response() != null) {
            HttpResponse resp = item.response();
            String respBody = resp.bodyToString();
            if (respBody != null && !respBody.isBlank()) {
                String contentType = resp.headerValue("Content-Type");
                if (contentType == null) {
                    contentType = "";
                }
                contentType = contentType.toLowerCase();

                if (contentType.contains("application/json") || isLikelyJson(respBody)) {
                    extractJsonParameters(item, respBody, ParameterSource_littlespidy.RESPONSE_BODY, url, statusCode, method, now, parameterMap);
                } else if (contentType.contains("text/html") || contentType.contains("application/xhtml") || respBody.contains("<form") || respBody.contains("<input")) {
                    extractXmlHtmlParameters(item, respBody, ParameterSource_littlespidy.RESPONSE_BODY, url, statusCode, method, now, parameterMap);
                } else if (contentType.contains("xml") || respBody.trim().startsWith("<?xml") || respBody.trim().startsWith("<")) {
                    extractXmlHtmlParameters(item, respBody, ParameterSource_littlespidy.RESPONSE_BODY, url, statusCode, method, now, parameterMap);
                } else if (contentType.contains("application/x-www-form-urlencoded") || (respBody.contains("=") && respBody.contains("&"))) {
                    extractFormUrlencodedParameters(item, respBody, ParameterSource_littlespidy.RESPONSE_BODY, url, statusCode, method, now, parameterMap);
                }
            }
        }
    }

    private boolean isLikelyJson(String text) {
        String trimmed = text.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    private void extractJsonParameters(
            HttpRequestResponse item,
            String body,
            ParameterSource_littlespidy source,
            String url,
            short statusCode,
            String method,
            LocalDateTime now,
            Map<String, ParameterEntry_littlespidy> parameterMap
    ) {
        try {
            JsonElement root = JsonParser.parseString(body);
            traverseJsonElement(root, "", item, source, url, statusCode, method, now, parameterMap);
        } catch (Exception ignored) {
            // Fallback: regex search for JSON keys if partial JSON
            Pattern jsonKeyPattern = Pattern.compile("\"([a-zA-Z0-9_.-]+)\"\\s*:\\s*(\"[^\"]*\"|[^,}\\]]+)");
            Matcher matcher = jsonKeyPattern.matcher(body);
            while (matcher.find()) {
                String key = matcher.group(1);
                String val = matcher.group(2).trim();
                if (val.startsWith("\"") && val.endsWith("\"") && val.length() >= 2) {
                    val = val.substring(1, val.length() - 1);
                }
                registerParameter(key, val, "JSON", source, item, url, statusCode, method, now, parameterMap);
            }
        }
    }

    private void traverseJsonElement(
            JsonElement element,
            String prefix,
            HttpRequestResponse item,
            ParameterSource_littlespidy source,
            String url,
            short statusCode,
            String method,
            LocalDateTime now,
            Map<String, ParameterEntry_littlespidy> parameterMap
    ) {
        if (element == null) {
            return;
        }

        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String key = entry.getKey();
                String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
                JsonElement valElem = entry.getValue();

                String valStr = "";
                if (valElem != null && valElem.isJsonPrimitive()) {
                    valStr = valElem.getAsString();
                } else if (valElem != null && (valElem.isJsonObject() || valElem.isJsonArray())) {
                    valStr = "[Object/Array]";
                }

                registerParameter(key, valStr, "JSON", source, item, url, statusCode, method, now, parameterMap);

                if (valElem != null && (valElem.isJsonObject() || valElem.isJsonArray())) {
                    traverseJsonElement(valElem, fullKey, item, source, url, statusCode, method, now, parameterMap);
                }
            }
        } else if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            for (JsonElement itemElem : arr) {
                traverseJsonElement(itemElem, prefix, item, source, url, statusCode, method, now, parameterMap);
            }
        }
    }

    private void extractFormUrlencodedParameters(
            HttpRequestResponse item,
            String body,
            ParameterSource_littlespidy source,
            String url,
            short statusCode,
            String method,
            LocalDateTime now,
            Map<String, ParameterEntry_littlespidy> parameterMap
    ) {
        Matcher matcher = FORM_PAIR_PATTERN.matcher(body);
        while (matcher.find()) {
            String rawKey = matcher.group(1);
            String rawVal = matcher.group(2);
            try {
                String key = URLDecoder.decode(rawKey.trim(), StandardCharsets.UTF_8);
                String val = URLDecoder.decode(rawVal != null ? rawVal.trim() : "", StandardCharsets.UTF_8);
                if (!key.isBlank()) {
                    registerParameter(key, val, "Form", source, item, url, statusCode, method, now, parameterMap);
                }
            } catch (Exception ex) {
                registerParameter(rawKey.trim(), rawVal != null ? rawVal.trim() : "", "Form", source, item, url, statusCode, method, now, parameterMap);
            }
        }
    }

    private void extractMultipartParameters(
            HttpRequestResponse item,
            String body,
            ParameterSource_littlespidy source,
            String url,
            short statusCode,
            String method,
            LocalDateTime now,
            Map<String, ParameterEntry_littlespidy> parameterMap
    ) {
        Matcher matcher = MULTIPART_NAME_PATTERN.matcher(body);
        while (matcher.find()) {
            String paramName = matcher.group(1).trim();
            if (!paramName.isBlank()) {
                registerParameter(paramName, "", "Multipart", source, item, url, statusCode, method, now, parameterMap);
            }
        }
    }

    private void extractXmlHtmlParameters(
            HttpRequestResponse item,
            String body,
            ParameterSource_littlespidy source,
            String url,
            short statusCode,
            String method,
            LocalDateTime now,
            Map<String, ParameterEntry_littlespidy> parameterMap
    ) {
        // HTML form input elements
        Matcher inputMatcher = HTML_INPUT_PATTERN.matcher(body);
        while (inputMatcher.find()) {
            String name = inputMatcher.group(1).trim();
            if (!name.isBlank()) {
                String fullTag = inputMatcher.group(0);
                String val = extractAttributeValue(fullTag, "value");
                registerParameter(name, val, "HTML", source, item, url, statusCode, method, now, parameterMap);
            }
        }

        // XML elements if XML document
        if (body.contains("<?xml") || (body.trim().startsWith("<") && !body.contains("<html") && !body.contains("<!DOCTYPE html"))) {
            Matcher xmlMatcher = XML_TAG_PATTERN.matcher(body);
            while (xmlMatcher.find()) {
                String tagName = xmlMatcher.group(1).trim();
                if (!tagName.equalsIgnoreCase("xml") && !tagName.isBlank() && tagName.length() < 64) {
                    registerParameter(tagName, "", "XML", source, item, url, statusCode, method, now, parameterMap);
                }
            }
        }
    }

    private String extractAttributeValue(String tag, String attrName) {
        Pattern p = Pattern.compile("\\b" + Pattern.quote(attrName) + "=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(tag);
        if (m.find()) {
            return m.group(1);
        }
        return "";
    }

    private void registerParameter(
            String name,
            String value,
            String format,
            ParameterSource_littlespidy source,
            HttpRequestResponse item,
            String url,
            short statusCode,
            String method,
            LocalDateTime now,
            Map<String, ParameterEntry_littlespidy> parameterMap
    ) {
        if (name == null || name.isBlank()) {
            return;
        }
        String cleanName = name.trim();
        if (cleanName.length() > 150) {
            cleanName = cleanName.substring(0, 150);
        }

        ParameterEntry_littlespidy entry = parameterMap.computeIfAbsent(cleanName, ParameterEntry_littlespidy::new);
        ParameterOccurrence_littlespidy occurrence = new ParameterOccurrence_littlespidy(
                item,
                source,
                format,
                value,
                url,
                statusCode,
                method,
                now
        );
        entry.addOccurrence(occurrence);
    }
}
