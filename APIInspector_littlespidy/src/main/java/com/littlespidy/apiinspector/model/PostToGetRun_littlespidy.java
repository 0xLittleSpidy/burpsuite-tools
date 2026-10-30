// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.model;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Encapsulates a saved POST-to-GET test runner session.
 */
public class PostToGetRun_littlespidy {

    private final String id;
    private String name;
    private final long timestamp;
    private final List<PostToGetTestResult_littlespidy> results = new ArrayList<>();

    public PostToGetRun_littlespidy(String name, List<PostToGetTestResult_littlespidy> results) {
        this(UUID.randomUUID().toString(), name, System.currentTimeMillis(), results);
    }

    public PostToGetRun_littlespidy(String id, String name, long timestamp, List<PostToGetTestResult_littlespidy> results) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.name = name != null ? name : "POST to GET Runner";
        this.timestamp = timestamp > 0 ? timestamp : System.currentTimeMillis();
        if (results != null) {
            this.results.addAll(results);
        }
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public long getTimestamp() { return timestamp; }
    public List<PostToGetTestResult_littlespidy> getResults() { return new ArrayList<>(results); }

    public void setResults(List<PostToGetTestResult_littlespidy> newResults) {
        this.results.clear();
        if (newResults != null) {
            this.results.addAll(newResults);
        }
    }

    public void addResult(PostToGetTestResult_littlespidy res) {
        if (res != null) {
            this.results.add(res);
        }
    }

    @Override
    public String toString() {
        return name;
    }
}
