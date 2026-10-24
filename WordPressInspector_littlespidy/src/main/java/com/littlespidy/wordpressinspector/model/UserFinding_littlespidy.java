// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.model;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Model for an enumerated WordPress user.
 */
public class UserFinding_littlespidy {
    private int id;
    private String username;
    private String displayName;
    private String slug;
    private String profileUrl;
    private String vector; // e.g. "REST API (/wp-json/wp/v2/users)", "Author Redirect (/?author=N)"

    public UserFinding_littlespidy() {
    }

    public UserFinding_littlespidy(int id, String username, String displayName, String slug, String vector) {
        this.id = id;
        this.username = username;
        this.displayName = displayName;
        this.slug = slug;
        this.vector = vector;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return username != null ? username : "";
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDisplayName() {
        return displayName != null ? displayName : username;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getSlug() {
        return slug != null ? slug : "";
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public String getProfileUrl() {
        return profileUrl != null ? profileUrl : "";
    }

    public void setProfileUrl(String profileUrl) {
        this.profileUrl = profileUrl;
    }

    public String getVector() {
        return vector != null ? vector : "Unknown Vector";
    }

    public void setVector(String vector) {
        this.vector = vector;
    }
}
