// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.engine;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.payloadinjector.model.InjectionSettings;
import com.littlespidy.payloadinjector.model.ParamPayloadEntry;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Engine responsible for computing and injecting parameter-attributed payloads
 * into HTTP requests across URL, Form-Body, JSON, and Cookie parameters.
 *
 * @author littlespidy
 */
public class ParamPayloadInjectorEngine {

    /**
     * Injects the given payload into all applicable parameters enabled in the settings.
     */
    public static HttpRequest injectAll(HttpRequest request, ParamPayloadEntry entry, InjectionSettings settings) {
        if (request == null || entry == null || settings == null) {
            return request;
        }

        List<ParsedHttpParameter> params = request.parameters();
        if (params == null || params.isEmpty()) {
            return request;
        }

        List<HttpParameter> updatedParams = new ArrayList<>();

        for (ParsedHttpParameter p : params) {
            if (!isTargetParameterType(p.type(), settings)) {
                continue;
            }

            String paramName = p.name();
            String originalValue = p.value();
            String renderedPayload = entry.render(paramName, originalValue);

            String finalValue = calculateFinalValue(originalValue, renderedPayload, settings.getInjectionMode());
            String encodedValue = applyEncoding(finalValue, p.type(), settings.getEncodingMode());

            updatedParams.add(HttpParameter.parameter(paramName, encodedValue, p.type()));
        }

        if (updatedParams.isEmpty()) {
            return request;
        }

        return request.withUpdatedParameters(updatedParams);
    }

    /**
     * Injects the given payload template into an arbitrary selected range in the request message.
     */
    public static HttpRequest injectSelection(HttpRequest request, Range range, ParamPayloadEntry entry, InjectionSettings settings) {
        if (request == null || range == null || entry == null) {
            return request;
        }

        int start = range.startIndexInclusive();
        int end = range.endIndexExclusive();

        String requestStr = request.toString();
        if (start < 0 || end > requestStr.length() || start >= end) {
            return request;
        }

        String selectedText = requestStr.substring(start, end);
        String paramName = inferParamName(requestStr, start, selectedText);
        String rendered = entry.render(paramName, selectedText);
        String finalReplacement = calculateFinalValue(selectedText, rendered, settings.getInjectionMode());

        String newRequestStr = requestStr.substring(0, start) + finalReplacement + requestStr.substring(end);
        return HttpRequest.httpRequest(request.httpService(), ByteArray.byteArray(newRequestStr.getBytes(StandardCharsets.UTF_8)));
    }

    private static String calculateFinalValue(String originalValue, String payload, InjectionSettings.InjectionMode mode) {
        if (originalValue == null) originalValue = "";
        return switch (mode) {
            case REPLACE -> payload;
            case APPEND -> originalValue + payload;
            case PREPEND -> payload + originalValue;
        };
    }

    private static String applyEncoding(String value, HttpParameterType type, InjectionSettings.EncodingMode mode) {
        if (value == null) return "";

        return switch (mode) {
            case NONE -> value;
            case URL_ENCODE -> urlEncode(value);
            case AUTO -> {
                if (type == HttpParameterType.JSON) {
                    yield escapeForJson(value);
                } else if (type == HttpParameterType.COOKIE) {
                    yield urlEncode(value);
                } else {
                    yield urlEncode(value);
                }
            }
        };
    }

    private static String urlEncode(String input) {
        try {
            return URLEncoder.encode(input, StandardCharsets.UTF_8.name())
                    .replace("+", "%20");
        } catch (Exception e) {
            return input;
        }
    }

    private static String escapeForJson(String input) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '"' && (i == 0 || input.charAt(i - 1) != '\\')) {
                sb.append("\\\"");
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean isTargetParameterType(HttpParameterType type, InjectionSettings settings) {
        return switch (type) {
            case URL -> settings.isTargetUrlParams();
            case BODY -> settings.isTargetBodyParams();
            case JSON -> settings.isTargetJsonParams();
            case COOKIE -> settings.isTargetCookieParams();
            default -> false;
        };
    }

    private static String inferParamName(String fullText, int startIndex, String selectedText) {
        if (startIndex <= 0) return selectedText;

        int searchBack = Math.max(0, startIndex - 50);
        String prefix = fullText.substring(searchBack, startIndex);

        int eqIdx = prefix.lastIndexOf('=');
        if (eqIdx != -1) {
            int startOfName = Math.max(prefix.lastIndexOf('&', eqIdx), prefix.lastIndexOf('?', eqIdx));
            if (startOfName == -1) startOfName = prefix.lastIndexOf('\n', eqIdx);
            if (startOfName == -1) startOfName = 0;
            else startOfName++;

            String name = prefix.substring(startOfName, eqIdx).trim();
            if (!name.isEmpty()) return name;
        }

        int colonIdx = prefix.lastIndexOf(':');
        if (colonIdx != -1) {
            int quoteEnd = prefix.lastIndexOf('"', colonIdx);
            if (quoteEnd != -1) {
                int quoteStart = prefix.lastIndexOf('"', quoteEnd - 1);
                if (quoteStart != -1) {
                    String name = prefix.substring(quoteStart + 1, quoteEnd).trim();
                    if (!name.isEmpty()) return name;
                }
            }
        }

        return selectedText;
    }
}
