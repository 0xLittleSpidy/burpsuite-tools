// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.model;

/**
 * Lifecycle states for a tracked session expiration task.
 *
 * @author littlespidy
 */
public enum SessionState {
    PENDING("Pending", "Awaiting scheduled probe milestone"),
    RUNNING("Running", "Probe request is currently in flight"),
    ACTIVE("Active", "Session verified alive and active (matches baseline)"),
    EXPIRED("Expired", "Session expired or invalidated (remaining timers cancelled)"),
    COMPLETED("Completed", "All scheduled milestones completed with session intact"),
    CANCELLED("Cancelled", "Timers were manually cancelled"),
    ERROR("Error", "Probe encountered connection or network error");

    private final String displayName;
    private final String description;

    SessionState(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
