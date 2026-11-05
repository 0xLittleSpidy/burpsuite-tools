// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.model;

public enum SSRFModuleCategory_littlespidy {
    PROTOCOL("Protocol Scheme"),
    CLOUD("Cloud Metadata"),
    SERVICE("Service Exploit");

    private final String displayName;

    SSRFModuleCategory_littlespidy(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
