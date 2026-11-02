// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Grouped entry representing a unique parameter name across all analyzed HTTP requests and responses.
 */
public class ParameterEntry_littlespidy {

    private final String name;
    private final Set<ParameterSource_littlespidy> sources = new LinkedHashSet<>();
    private final Set<String> formats = new LinkedHashSet<>();
    private final Set<String> sampleValues = new LinkedHashSet<>();
    private final List<ParameterOccurrence_littlespidy> occurrences = new ArrayList<>();

    public ParameterEntry_littlespidy(String name) {
        this.name = name;
    }

    public synchronized void addOccurrence(ParameterOccurrence_littlespidy occurrence) {
        if (occurrence == null) {
            return;
        }
        occurrences.add(occurrence);
        if (occurrence.getSource() != null) {
            sources.add(occurrence.getSource());
        }
        if (occurrence.getFormat() != null && !occurrence.getFormat().isBlank()) {
            formats.add(occurrence.getFormat());
        }
        if (occurrence.getValue() != null && !occurrence.getValue().isBlank() && sampleValues.size() < 10) {
            String val = occurrence.getValue().trim();
            if (val.length() > 60) {
                val = val.substring(0, 57) + "...";
            }
            sampleValues.add(val);
        }
    }

    public String getName() {
        return name;
    }

    public synchronized int getOccurrenceCount() {
        return occurrences.size();
    }

    public synchronized List<ParameterOccurrence_littlespidy> getOccurrences() {
        return Collections.unmodifiableList(new ArrayList<>(occurrences));
    }

    public synchronized String getSourceDisplay() {
        boolean req = sources.contains(ParameterSource_littlespidy.REQUEST_BODY);
        boolean resp = sources.contains(ParameterSource_littlespidy.RESPONSE_BODY);
        if (req && resp) {
            return "Both";
        } else if (req) {
            return "Request Body";
        } else if (resp) {
            return "Response Body";
        }
        return "Unknown";
    }

    public synchronized String getFormatDisplay() {
        if (formats.isEmpty()) {
            return "Unknown";
        }
        return String.join(", ", formats);
    }

    public synchronized String getSampleValuesDisplay() {
        if (sampleValues.isEmpty()) {
            return "-";
        }
        return String.join(", ", sampleValues);
    }
}
