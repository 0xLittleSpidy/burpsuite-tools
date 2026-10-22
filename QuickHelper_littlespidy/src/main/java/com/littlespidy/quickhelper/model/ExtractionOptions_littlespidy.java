// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.model;

/**
 * Configuration options for domain extraction from the Burp Suite site map.
 */
public class ExtractionOptions_littlespidy {
    private final boolean includeSchema;
    private final boolean inScopeOnly;

    public ExtractionOptions_littlespidy(boolean includeSchema, boolean inScopeOnly) {
        this.includeSchema = includeSchema;
        this.inScopeOnly = inScopeOnly;
    }

    public boolean isIncludeSchema() {
        return includeSchema;
    }

    public boolean isInScopeOnly() {
        return inScopeOnly;
    }

    public static ExtractionOptions_littlespidy allDomains() {
        return new ExtractionOptions_littlespidy(false, false);
    }

    public static ExtractionOptions_littlespidy allDomainsWithSchema() {
        return new ExtractionOptions_littlespidy(true, false);
    }

    public static ExtractionOptions_littlespidy inScopeDomains() {
        return new ExtractionOptions_littlespidy(false, true);
    }

    public static ExtractionOptions_littlespidy inScopeDomainsWithSchema() {
        return new ExtractionOptions_littlespidy(true, true);
    }
}
