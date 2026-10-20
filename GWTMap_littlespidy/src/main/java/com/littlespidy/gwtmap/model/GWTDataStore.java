// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.model;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Thread-safe centralized datastore for GWT findings (module info, services,
 * methods, raw and cleaned JavaScript).
 *
 * @author littlespidy
 */
public class GWTDataStore {

    private GWTModuleInfo moduleInfo = new GWTModuleInfo();
    private final List<GWTService> services = new CopyOnWriteArrayList<>();
    private final List<GWTMethod> methods = new CopyOnWriteArrayList<>();
    private final List<GwtHttpHistoryEntry> httpHistory = new CopyOnWriteArrayList<>();
    private String rawCode = "";
    private String cleanedCode = "";

    public synchronized void reset() {
        moduleInfo = new GWTModuleInfo();
        services.clear();
        methods.clear();
        httpHistory.clear();
        rawCode = "";
        cleanedCode = "";
    }

    public synchronized void addHttpHistoryEntry(GwtHttpHistoryEntry entry) {
        if (entry != null) {
            httpHistory.add(entry);
        }
    }

    public List<GwtHttpHistoryEntry> getHttpHistory() {
        return new ArrayList<>(httpHistory);
    }

    public synchronized void clearHttpHistory() {
        httpHistory.clear();
    }

    public synchronized GWTModuleInfo getModuleInfo() {
        return moduleInfo;
    }

    public synchronized void setModuleInfo(GWTModuleInfo info) {
        this.moduleInfo = info != null ? info : new GWTModuleInfo();
    }

    public synchronized void addService(GWTService service) {
        if (service != null && !services.contains(service)) {
            services.add(service);
        }
    }

    public synchronized void setServices(List<GWTService> newServices) {
        services.clear();
        if (newServices != null) {
            services.addAll(newServices);
        }
    }

    public List<GWTService> getAllServices() {
        return new ArrayList<>(services);
    }

    public synchronized void addMethod(GWTMethod method) {
        if (method != null) {
            methods.add(method);
        }
    }

    public synchronized void setMethods(List<GWTMethod> newMethods) {
        methods.clear();
        if (newMethods != null) {
            methods.addAll(newMethods);
        }
    }

    public List<GWTMethod> getAllMethods() {
        return new ArrayList<>(methods);
    }

    public synchronized String getRawCode() {
        return rawCode;
    }

    public synchronized void setRawCode(String code) {
        this.rawCode = code != null ? code : "";
    }

    public synchronized String getCleanedCode() {
        return cleanedCode;
    }

    public synchronized void setCleanedCode(String code) {
        this.cleanedCode = code != null ? code : "";
    }

    // -- Filtering Logic ------------------------------------------------------

    public static boolean matchesMethod(String method, Set<String> selectedMethods) {
        if (selectedMethods == null || selectedMethods.isEmpty()) return true;
        if (method == null) return false;
        return selectedMethods.contains(method.toUpperCase());
    }

    public static boolean matchesStatusCode(int statusCode, String filter) {
        if (filter == null || filter.trim().isEmpty() || filter.equalsIgnoreCase("All") || filter.equalsIgnoreCase("All Statuses")) {
            return true;
        }
        if (filter.equalsIgnoreCase("Probed")) {
            return statusCode > 0;
        }
        if (filter.equalsIgnoreCase("Unprobed")) {
            return statusCode <= 0;
        }
        if (statusCode <= 0) return false;

        String[] tokens = filter.split("[,/\\s]+");
        for (String rawToken : tokens) {
            String token = rawToken.trim();
            if (token.isEmpty()) continue;

            if (token.equalsIgnoreCase("2xx") && statusCode >= 200 && statusCode < 300) return true;
            if (token.equalsIgnoreCase("3xx") && statusCode >= 300 && statusCode < 400) return true;
            if (token.equalsIgnoreCase("4xx") && statusCode >= 400 && statusCode < 500) return true;
            if (token.equalsIgnoreCase("5xx") && statusCode >= 500 && statusCode < 600) return true;

            try {
                int targetCode = Integer.parseInt(token);
                if (statusCode == targetCode) return true;
            } catch (NumberFormatException ignored) {}
        }
        return false;
    }

    /**
     * Filters methods by search text, selected service categories, status code,
     * HTTP method filter, and target scope.
     */
    public List<GWTMethod> getFilteredEntries(
            String textQuery,
            Set<String> selectedServices,
            String statusFilter,
            Set<String> methodFilter,
            Predicate<String> inScopePredicate) {

        String query = (textQuery != null) ? textQuery.trim().toLowerCase() : "";

        return methods.stream()
                .filter(m -> matchesMethod("POST", methodFilter))
                .filter(m -> matchesStatusCode(m.getProbeStatusCode(), statusFilter))
                .filter(m -> {
                    if (selectedServices == null || selectedServices.isEmpty()) return true;
                    return selectedServices.contains(m.getServiceCategory())
                            || (m.getService() != null && selectedServices.contains(m.getService().getServicePath()));
                })
                .filter(m -> {
                    if (inScopePredicate == null) return true;
                    return inScopePredicate.test(m.getFullEndpointUrl());
                })
                .filter(m -> {
                    if (query.isEmpty()) return true;
                    if (m.getMethodName().toLowerCase().contains(query)) return true;
                    if (m.getServiceCategory().toLowerCase().contains(query)) return true;
                    if (m.getRmtSvcIntName().toLowerCase().contains(query)) return true;
                    if (m.getFullEndpointUrl().toLowerCase().contains(query)) return true;
                    if (m.getMethodSignature().stream().anyMatch(s -> s.toLowerCase().contains(query))) return true;
                    return false;
                })
                .collect(Collectors.toList());
    }

    /**
     * Groups methods by a category mode (e.g. Service or Status) conforming to
     * extension architecture guidelines.
     */
    public Map<String, List<GWTMethod>> groupByMode(
            String mode,
            String textQuery,
            String statusFilter,
            String contentTypeFilter,
            Set<String> methodFilter,
            Predicate<String> inScopePredicate) {

        List<GWTMethod> filtered = getFilteredEntries(textQuery, null, statusFilter, methodFilter, inScopePredicate);
        Map<String, List<GWTMethod>> map = new LinkedHashMap<>();

        for (GWTMethod m : filtered) {
            String key;
            if ("Status".equalsIgnoreCase(mode)) {
                key = m.isProbed() ? "HTTP " + m.getProbeStatusCode() : "Unprobed";
            } else {
                key = m.getServiceCategory();
            }
            map.computeIfAbsent(key, k -> new ArrayList<>()).add(m);
        }
        return map;
    }
}
