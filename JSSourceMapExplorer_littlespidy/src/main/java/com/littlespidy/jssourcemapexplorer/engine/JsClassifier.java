// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import burp.api.montoya.MontoyaApi;

import java.util.Set;

/**
 * Classifies JavaScript scripts as 1st Party (App Owned) or 3rd Party (CDNs, Analytics, Trackers).
 *
 * @author littlespidy
 */
public class JsClassifier {

    private static final Set<String> KNOWN_THIRD_PARTY_HOSTS = Set.of(
        "google-analytics.com",
        "googletagmanager.com",
        "gstatic.com",
        "recaptcha.net",
        "cloudflare.com",
        "cdnjs.cloudflare.com",
        "unpkg.com",
        "jsdelivr.net",
        "stripe.com",
        "facebook.net",
        "connect.facebook.net",
        "hotjar.com",
        "sentry.io",
        "browser.sentry-cdn.com",
        "intercom.io",
        "widget.intercom.io",
        "segment.com",
        "cdn.segment.com",
        "mixpanel.com",
        "cdn.mxpnl.com",
        "fontawesome.com",
        "kit.fontawesome.com",
        "datadoghq-browser-agent.com",
        "amplitude.com",
        "cdn.amplitude.com",
        "branch.io",
        "doubleclick.net",
        "adroll.com",
        "hubspot.com",
        "js.hs-scripts.com",
        "fullstory.com",
        "cdn.optimizely.com",
        "chartbeat.com",
        "trustpilot.com",
        "clarity.ms",
        "criteo.com",
        "criteo.net"
    );

    public static boolean isFirstParty(MontoyaApi api, String url, String host) {
        if (url == null || host == null) return false;

        String lowerHost = host.toLowerCase();
        for (String thirdParty : KNOWN_THIRD_PARTY_HOSTS) {
            if (lowerHost.equals(thirdParty) || lowerHost.endsWith("." + thirdParty)) {
                return false;
            }
        }

        // If in Burp's target scope, consider it 1st party
        if (api != null && api.scope().isInScope(url)) {
            return true;
        }

        // Check for common CDN subdomains on otherwise generic domains
        if (lowerHost.startsWith("cdn.") || lowerHost.startsWith("assets.") || lowerHost.startsWith("static.")) {
            // If in scope, still 1st party assets
            if (api != null && api.scope().isInScope(url)) {
                return true;
            }
        }

        return api == null || api.scope().isInScope(url);
    }

    public static String getOriginLabel(boolean isFirstParty) {
        return isFirstParty ? "1st Party (App)" : "3rd Party (CDN/Tracker)";
    }
}
