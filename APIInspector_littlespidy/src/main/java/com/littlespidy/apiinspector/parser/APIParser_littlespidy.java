// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.parser;

/**
 * Common interface for API definition and collection parsers.
 */
public interface APIParser_littlespidy {

    /**
     * Inspects content to determine if this parser can handle it.
     */
    boolean canParse(String content);

    /**
     * Parses the content into an ImportedCollection.
     *
     * @param content        raw content (JSON or YAML)
     * @param sourceLocation filename or URL
     * @param sourceType     FILE or URL
     * @return ParseResult containing the collection or error details
     */
    ParseResult_littlespidy parse(String content, String sourceLocation, String sourceType);
}
