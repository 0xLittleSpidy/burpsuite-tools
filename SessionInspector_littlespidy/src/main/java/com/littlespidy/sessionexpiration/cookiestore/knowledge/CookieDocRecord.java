// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sessionexpiration.cookiestore.knowledge;

import java.awt.Color;
import java.util.List;

/**
 * Immutable record representing documentation, classification, and usage details
 * for a web cookie scraped from https://www.cookiesearch.org/.
 *
 * @author littlespidy
 */
public record CookieDocRecord(
        String name,
        String category,
        String cookieId,
        String url,
        String script,
        String description,
        String referenceUrl,
        List<String> related
) {

    public boolean hasUrl() {
        return url != null && !url.isBlank();
    }

    public boolean hasScript() {
        return script != null && !script.isBlank();
    }

    public boolean hasRelated() {
        return related != null && !related.isEmpty();
    }

    public boolean hasDescription() {
        return description != null && !description.isBlank();
    }

    /**
     * Returns an intuitive category badge background color.
     */
    public Color categoryColor() {
        if (category == null) return new Color(127, 140, 141);
        String cat = category.trim().toLowerCase();
        return switch (cat) {
            case "necessary" -> new Color(39, 174, 96);       // Green
            case "analytics" -> new Color(41, 128, 185);       // Blue
            case "advertisement" -> new Color(211, 84, 0);     // Orange/Amber
            case "functional" -> new Color(142, 68, 173);      // Purple
            case "performance" -> new Color(22, 160, 133);     // Teal
            default -> new Color(127, 140, 141);               // Neutral Gray
        };
    }
}
