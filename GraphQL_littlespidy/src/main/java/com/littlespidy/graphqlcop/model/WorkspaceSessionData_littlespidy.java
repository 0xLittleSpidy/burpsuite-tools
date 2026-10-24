// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class WorkspaceSessionData_littlespidy implements Serializable {
    private static final long serialVersionUID = 1L;

    private String savedTimestamp;
    private List<SessionData_littlespidy> endpointTabs = new ArrayList<>();

    public WorkspaceSessionData_littlespidy() {}

    public String getSavedTimestamp() {
        return savedTimestamp;
    }

    public void setSavedTimestamp(String savedTimestamp) {
        this.savedTimestamp = savedTimestamp;
    }

    public List<SessionData_littlespidy> getEndpointTabs() {
        return endpointTabs;
    }

    public void setEndpointTabs(List<SessionData_littlespidy> endpointTabs) {
        this.endpointTabs = endpointTabs;
    }
}
