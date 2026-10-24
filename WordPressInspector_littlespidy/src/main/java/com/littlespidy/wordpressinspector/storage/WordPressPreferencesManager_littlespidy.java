// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wordpressinspector.storage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;
import com.littlespidy.wordpressinspector.model.ScanConfig_littlespidy;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Persists extension configurations and daily API usage metrics via Burp Preferences.
 */
public class WordPressPreferencesManager_littlespidy {

    private static final String PREF_API_KEY = "wordpress_inspector_api_key";
    private static final String PREF_LIVE_SCAN = "wordpress_inspector_live_scan";
    private static final String PREF_CACHE_24H = "wordpress_inspector_cache_24h";
    private static final String PREF_SMART_PRIORITY = "wordpress_inspector_smart_priority";
    private static final String PREF_WP_ORG_UPDATES = "wordpress_inspector_wp_org_updates";
    private static final String PREF_SECURITY_HARDENING = "wordpress_inspector_hardening";
    private static final String PREF_DAILY_COUNTER = "wordpress_inspector_daily_counter";
    private static final String PREF_RESET_DATE = "wordpress_inspector_reset_date";

    private final MontoyaApi api;

    public WordPressPreferencesManager_littlespidy(MontoyaApi api) {
        this.api = api;
    }

    public void loadPreferences(ScanConfig_littlespidy config) {
        if (api == null || api.persistence() == null) {
            return;
        }
        Preferences prefs = api.persistence().preferences();

        String key = prefs.getString(PREF_API_KEY);
        if (key != null) config.setWpscanApiKey(key);

        Boolean live = prefs.getBoolean(PREF_LIVE_SCAN);
        if (live != null) config.setLiveScanEnabled(live);

        Boolean cache = prefs.getBoolean(PREF_CACHE_24H);
        if (cache != null) config.setCache24hEnabled(cache);

        Boolean smart = prefs.getBoolean(PREF_SMART_PRIORITY);
        if (smart != null) config.setSmartPluginPriority(smart);

        Boolean wpOrg = prefs.getBoolean(PREF_WP_ORG_UPDATES);
        if (wpOrg != null) config.setCheckWpOrgUpdates(wpOrg);

        Boolean hardening = prefs.getBoolean(PREF_SECURITY_HARDENING);
        if (hardening != null) config.setSecurityHardeningChecks(hardening);

        Integer counter = prefs.getInteger(PREF_DAILY_COUNTER);
        String lastDate = prefs.getString(PREF_RESET_DATE);
        String today = new SimpleDateFormat("yyyy-MM-dd").format(new Date());

        if (lastDate == null || !lastDate.equals(today)) {
            // New day: reset counter
            config.setDailyApiCounter(0);
            config.setLastCounterResetDate(today);
            prefs.setInteger(PREF_DAILY_COUNTER, 0);
            prefs.setString(PREF_RESET_DATE, today);
        } else {
            config.setDailyApiCounter(counter != null ? counter : 0);
            config.setLastCounterResetDate(lastDate);
        }
    }

    public void savePreferences(ScanConfig_littlespidy config) {
        if (api == null || api.persistence() == null) {
            return;
        }
        Preferences prefs = api.persistence().preferences();
        prefs.setString(PREF_API_KEY, config.getWpscanApiKey());
        prefs.setBoolean(PREF_LIVE_SCAN, config.isLiveScanEnabled());
        prefs.setBoolean(PREF_CACHE_24H, config.isCache24hEnabled());
        prefs.setBoolean(PREF_SMART_PRIORITY, config.isSmartPluginPriority());
        prefs.setBoolean(PREF_WP_ORG_UPDATES, config.isCheckWpOrgUpdates());
        prefs.setBoolean(PREF_SECURITY_HARDENING, config.isSecurityHardeningChecks());
        prefs.setInteger(PREF_DAILY_COUNTER, config.getDailyApiCounter());
        prefs.setString(PREF_RESET_DATE, config.getLastCounterResetDate());
    }

    public void resetDailyCounter(ScanConfig_littlespidy config) {
        config.setDailyApiCounter(0);
        String today = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
        config.setLastCounterResetDate(today);
        if (api != null && api.persistence() != null) {
            Preferences prefs = api.persistence().preferences();
            prefs.setInteger(PREF_DAILY_COUNTER, 0);
            prefs.setString(PREF_RESET_DATE, today);
        }
    }
}
