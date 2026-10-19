// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.parser;

import java.util.ArrayList;
import java.util.List;

/**
 * Factory class that automatically identifies and instantiates the appropriate parser
 * for a given API specification or collection.
 */
public class APIParserFactory_littlespidy {

    private static final List<APIParser_littlespidy> PARSERS = new ArrayList<>();

    static {
        PARSERS.add(new OpenAPIParser_littlespidy());
        PARSERS.add(new SwaggerParser_littlespidy());
        PARSERS.add(new PostmanParser_littlespidy());
    }

    /**
     * Finds the matching parser for the content, or returns null if unsupported.
     */
    public static APIParser_littlespidy getParser(String content) {
        if (content == null || content.isBlank()) return null;
        for (APIParser_littlespidy parser : PARSERS) {
            if (parser.canParse(content)) {
                return parser;
            }
        }
        return null;
    }

    /**
     * Parses the content using the detected parser.
     *
     * @param content        raw content (JSON or YAML)
     * @param sourceLocation filename or URL
     * @param sourceType     FILE or URL
     * @return ParseResult containing the parsed collection or error
     */
    public static ParseResult_littlespidy parse(String content, String sourceLocation, String sourceType) {
        if (content == null || content.isBlank()) {
            return ParseResult_littlespidy.failure("Content is empty or null.");
        }

        APIParser_littlespidy parser = getParser(content);
        if (parser != null) {
            return parser.parse(content, sourceLocation, sourceType);
        }

        return ParseResult_littlespidy.failure(
                "Unsupported or invalid format. Expected OpenAPI 3.0/3.1 (JSON/YAML), " +
                "Swagger 2.0 (JSON/YAML), or Postman Collection v2.0/v2.1 (JSON)."
        );
    }
}
