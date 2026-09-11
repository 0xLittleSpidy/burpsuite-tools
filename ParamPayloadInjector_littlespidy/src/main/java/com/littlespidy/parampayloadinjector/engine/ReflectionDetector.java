package com.littlespidy.parampayloadinjector.engine;

import com.littlespidy.parampayloadinjector.model.InjectionConfig;
import com.littlespidy.parampayloadinjector.model.ReflectionFinding;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Passive HTTP handler that inspects responses for reflections of parameter-attributed
 * payloads (XSS, Angular CSTI, etc.) and dispatches findings with annotations.
 */
public class ReflectionDetector implements HttpHandler {

    private final MontoyaApi api;
    private final InjectionConfig config;
    private final Consumer<ReflectionFinding> findingConsumer;
    private final AtomicLong idCounter = new AtomicLong(1);
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

    public ReflectionDetector(MontoyaApi api, InjectionConfig config, Consumer<ReflectionFinding> findingConsumer) {
        this.api = api;
        this.config = config;
        this.findingConsumer = findingConsumer;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!config.isReflectionDetectionEnabled()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        HttpRequest request = responseReceived.initiatingRequest();
        if (request == null || !request.hasParameters()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        String responseBody = responseReceived.bodyToString();
        if (responseBody == null || responseBody.isEmpty()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        String responseBodyLower = responseBody.toLowerCase();
        Annotations annotations = responseReceived.annotations();
        boolean findingCreated = false;

        for (ParsedHttpParameter param : request.parameters()) {
            String paramName = param.name();
            String paramValue = param.value();
            if (paramValue == null || paramValue.length() < 3) {
                continue;
            }

            // Test both raw value and URL-decoded value
            String decodedValue = safeUrlDecode(paramValue);

            // Check if this parameter was injected with an attributed payload
            boolean isAttributed = isAttributedPayload(paramName, paramValue, decodedValue);
            if (!isAttributed) {
                continue;
            }

            // Determine if the payload (or key parts) reflected in the response
            String matchedSignature = null;
            if (responseBody.contains(decodedValue)) {
                matchedSignature = decodedValue;
            } else if (responseBody.contains(paramValue)) {
                matchedSignature = paramValue;
            } else if (isAngularPayload(decodedValue) && matchesAngularCanary(decodedValue, responseBody)) {
                matchedSignature = "{{...}} or eval result";
            }

            if (matchedSignature != null) {
                findingCreated = true;
                String category = categorizePayload(decodedValue);
                String context = analyzeReflectionContext(responseBody, matchedSignature);
                String evidence = extractEvidenceSnippet(responseBody, matchedSignature);

                // Safe-append note according to coding standards
                if (config.isAnnotateBurpHistory()) {
                    String existingNote = annotations.notes();
                    String newNote = "Reflected: param '" + paramName + "' (" + category + ")";
                    if (existingNote == null || existingNote.isEmpty()) {
                        annotations.setNotes(newNote);
                    } else if (!existingNote.contains(newNote)) {
                        annotations.setNotes(existingNote + " | " + newNote);
                    }

                    if (context.contains("HTML Tag Body") || context.contains("Script Block")) {
                        annotations.setHighlightColor(HighlightColor.RED);
                    } else {
                        annotations.setHighlightColor(HighlightColor.YELLOW);
                    }
                }

                HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(
                        request,
                        responseReceived,
                        annotations
                );

                ReflectionFinding finding = new ReflectionFinding(
                        idCounter.getAndIncrement(),
                        LocalDateTime.now().format(TIME_FORMATTER),
                        request.method(),
                        request.url(),
                        responseReceived.statusCode(),
                        paramName,
                        category,
                        decodedValue,
                        context,
                        evidence,
                        rr
                );

                if (findingConsumer != null) {
                    findingConsumer.accept(finding);
                }
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived, annotations);
    }

    private boolean isAttributedPayload(String paramName, String rawValue, String decodedValue) {
        String testVal = decodedValue.toLowerCase();
        String testParam = paramName.toLowerCase();

        // Parameter attribution checks:
        // 1. alert('param_name') or alert("param_name")
        if (testVal.contains("alert('" + testParam + "')") || testVal.contains("alert(\"" + testParam + "\")")
                || testVal.contains("alert(`" + testParam + "`)") || testVal.contains("alert(" + testParam + ")")) {
            return true;
        }

        // 2. Angular CSTI with parameter name: {{'param_name'}} or /* param_name */
        if (testVal.contains("{{") && testVal.contains("}}") && testVal.contains(testParam)) {
            return true;
        }

        // 3. Generic XSS tags containing parameter name
        if ((testVal.contains("<script") || testVal.contains("onerror=") || testVal.contains("onload="))
                && testVal.contains(testParam)) {
            return true;
        }

        return false;
    }

    private boolean isAngularPayload(String payload) {
        return payload.contains("{{") && payload.contains("}}");
    }

    private boolean matchesAngularCanary(String payload, String responseBody) {
        // Check for math evaluation, e.g. {{7*7}} -> 49
        if (payload.contains("7*7") && responseBody.contains("49")) {
            return true;
        }
        return false;
    }

    private String categorizePayload(String payload) {
        if (payload.contains("{{") || payload.contains("$eval") || payload.contains("$on")) {
            return "Angular CSTI";
        }
        if (payload.contains("<script") || payload.contains("alert(") || payload.contains("onerror=") || payload.contains("onload=")) {
            return "XSS";
        }
        return "Custom";
    }

    private String analyzeReflectionContext(String body, String signature) {
        int idx = body.indexOf(signature);
        if (idx == -1) {
            return "Raw Response Body";
        }

        int lookBack = Math.max(0, idx - 200);
        String before = body.substring(lookBack, idx);
        int lookAhead = Math.min(body.length(), idx + signature.length() + 200);
        String after = body.substring(idx + signature.length(), lookAhead);

        String beforeLower = before.toLowerCase();
        int lastScriptOpen = beforeLower.lastIndexOf("<script");
        int lastScriptClose = beforeLower.lastIndexOf("</script");
        if (lastScriptOpen != -1 && (lastScriptClose == -1 || lastScriptOpen > lastScriptClose)) {
            return "Script Block";
        }

        int lastOpenAngle = before.lastIndexOf('<');
        int lastCloseAngle = before.lastIndexOf('>');
        if (lastOpenAngle > lastCloseAngle) {
            return "HTML Attribute";
        }

        if (signature.contains("{{") || before.endsWith("{{") || after.startsWith("}}")) {
            return "Angular Template";
        }

        if (lastCloseAngle != -1 && after.contains("<")) {
            return "HTML Tag Body";
        }

        return "Raw Response Body";
    }

    private String extractEvidenceSnippet(String body, String signature) {
        int idx = body.indexOf(signature);
        if (idx == -1) {
            return signature;
        }

        int start = Math.max(0, idx - 40);
        int end = Math.min(body.length(), idx + signature.length() + 40);
        String snippet = body.substring(start, end).replace('\r', ' ').replace('\n', ' ');
        return (start > 0 ? "..." : "") + snippet + (end < body.length() ? "..." : "");
    }

    private String safeUrlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            return value;
        }
    }
}
