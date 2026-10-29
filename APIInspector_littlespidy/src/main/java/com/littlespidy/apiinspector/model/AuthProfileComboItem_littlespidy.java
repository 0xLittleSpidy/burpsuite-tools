// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

/**
 * Wrapper for displaying an AuthProfile in Swing JComboBox components.
 */
public class AuthProfileComboItem_littlespidy {

    public final AuthProfile_littlespidy profile;
    public final String label;

    public AuthProfileComboItem_littlespidy(AuthProfile_littlespidy profile, String label) {
        this.profile = profile;
        this.label = label != null ? label : "";
    }

    public AuthProfile_littlespidy getProfile() {
        return profile;
    }

    public String getLabel() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}
