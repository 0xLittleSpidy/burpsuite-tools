// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Represents XML-RPC testing findings.
 */
public class XmlRpcResult_littlespidy {
    private boolean enabled;
    private boolean pingback;
    private boolean multicall;
    private String details = "Not Tested";

    public XmlRpcResult_littlespidy() {
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isPingback() {
        return pingback;
    }

    public void setPingback(boolean pingback) {
        this.pingback = pingback;
    }

    public boolean isMulticall() {
        return multicall;
    }

    public void setMulticall(boolean multicall) {
        this.multicall = multicall;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getStatusSummary() {
        if (!enabled) {
            return "Disabled / Inaccessible";
        }
        if (pingback && multicall) {
            return "Enabled (Pingback + Multicall Active)";
        }
        if (pingback) {
            return "Enabled (Pingback Active)";
        }
        if (multicall) {
            return "Enabled (Multicall Active)";
        }
        return "Enabled";
    }
}
