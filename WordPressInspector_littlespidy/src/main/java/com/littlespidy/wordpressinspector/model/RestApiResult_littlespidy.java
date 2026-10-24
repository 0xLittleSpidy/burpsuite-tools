// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Represents REST API discovery and exposure findings.
 */
public class RestApiResult_littlespidy {
    private boolean usersExposed;
    private boolean postsExposed;
    private List<RestEndpoint_littlespidy> endpoints = new ArrayList<>();

    public RestApiResult_littlespidy() {
    }

    public boolean isUsersExposed() {
        return usersExposed;
    }

    public void setUsersExposed(boolean usersExposed) {
        this.usersExposed = usersExposed;
    }

    public boolean isPostsExposed() {
        return postsExposed;
    }

    public void setPostsExposed(boolean postsExposed) {
        this.postsExposed = postsExposed;
    }

    public List<RestEndpoint_littlespidy> getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(List<RestEndpoint_littlespidy> endpoints) {
        this.endpoints = endpoints != null ? endpoints : new ArrayList<>();
    }

    public void addEndpoint(String path, String name, boolean accessible) {
        this.endpoints.add(new RestEndpoint_littlespidy(path, name, accessible));
    }

    public static class RestEndpoint_littlespidy {
        private String path;
        private String name;
        private boolean accessible;

        public RestEndpoint_littlespidy(String path, String name, boolean accessible) {
            this.path = path;
            this.name = name;
            this.accessible = accessible;
        }

        public String getPath() {
            return path;
        }

        public String getName() {
            return name;
        }

        public boolean isAccessible() {
            return accessible;
        }
    }
}
