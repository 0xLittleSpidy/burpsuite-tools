// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.convertposttoget.ui;

import com.littlespidy.convertposttoget.model.ConversionResult;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Collapsible filter sidebar for the Convert POST to GET session results.
 * Follows extension_architecture.md with Smart Pattern Suppression, MultiSelectFilterButtons,
 * Core Triage Filters, Quick Presets, and 300ms Debouncing.
 *
 * @author littlespidy
 */
public class ConvertFilterPanel extends JPanel {

    // ── Smart Filter Section ──
    private final JCheckBox smartFilterCheckbox = new JCheckBox("Enable Smart Filter (auto-hide repeat signatures)", false);
    private final JCheckBox hideMethodNotAllowedCheckbox = new JCheckBox("Hide 405 Method Not Allowed / 501", false);
    private final JCheckBox anomaliesOnlyCheckbox = new JCheckBox("Show Anomalies / High & Medium Only", false);

    // ── MultiSelect Filter Buttons ──
    private final MultiSelectFilterButton signalFilterBtn = new MultiSelectFilterButton(
        "Signal",
        List.of(
            "All Signals",
            "Bypass Detected (403/401 -> 200)",
            "Method Permitted / CSRF Potential",
            "5xx Server Error",
            "Redirect Maintained",
            "Status Changed",
            "Method Not Allowed"
        ),
        sel -> triggerDebouncedFilter()
    );

    private final MultiSelectFilterButton severityFilterBtn = new MultiSelectFilterButton(
        "Severity",
        List.of(
            "All Severities",
            "High",
            "Medium",
            "Low",
            "Info"
        ),
        sel -> triggerDebouncedFilter()
    );

    private final MultiSelectFilterButton getStatusFilterBtn = new MultiSelectFilterButton(
        "GET Status",
        List.of(
            "All GET Statuses",
            "2xx Success",
            "200 OK",
            "3xx Redirect",
            "302 Redirect",
            "4xx Client Error",
            "401 Unauthorized",
            "403 Forbidden",
            "404 Not Found",
            "405 Method Not Allowed",
            "5xx Server Error",
            "500 Internal Error"
        ),
        sel -> triggerDebouncedFilter()
    );

    private final MultiSelectFilterButton contentTypeFilterBtn = new MultiSelectFilterButton(
        "Content-Type",
        List.of(
            "All Content-Types",
            "JSON",
            "HTML",
            "XML",
            "Plain Text",
            "Other"
        ),
        sel -> triggerDebouncedFilter()
    );

    // ── Manual Inputs ──
    private final JTextField domainField = new JTextField(12);
    private final JTextField minLengthField = new JTextField(6);
    private final JTextField maxLengthField = new JTextField(6);
    private final JTextField evidenceSearchField = new JTextField(12);
    private final JCheckBox regexSearchCheckBox = new JCheckBox("Regex", false);
    private final JCheckBox matchCaseCheckBox = new JCheckBox("Match Case", false);

    private final JLabel statsLabel = new JLabel("Total: 0 | Displayed: 0");

    private final Consumer<java.util.function.Predicate<ConversionResult>> filterCallback;
    private final Map<String, Integer> smartFilterSignatures = new ConcurrentHashMap<>();

    // 300ms Debounce Timer
    private final javax.swing.Timer debounceTimer = new javax.swing.Timer(300, e -> applyFilter());
    {
        debounceTimer.setRepeats(false);
    }

    public ConvertFilterPanel(Consumer<java.util.function.Predicate<ConversionResult>> filterCallback) {
        this.filterCallback = filterCallback;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ── 1. Smart Filter Section ──
        JPanel smartPanel = new JPanel(new GridLayout(0, 1, 2, 2));
        smartPanel.setBorder(new TitledBorder("Smart Pattern Suppression"));
        smartPanel.add(smartFilterCheckbox);
        smartPanel.add(hideMethodNotAllowedCheckbox);
        smartPanel.add(anomaliesOnlyCheckbox);

        smartFilterCheckbox.addActionListener(e -> applyFilter());
        hideMethodNotAllowedCheckbox.addActionListener(e -> applyFilter());
        anomaliesOnlyCheckbox.addActionListener(e -> applyFilter());

        add(smartPanel);
        add(Box.createVerticalStrut(6));

        // ── 2. Preset Chips Section ──
        JPanel presetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        presetPanel.setBorder(new TitledBorder("Quick Triage Presets"));

        JButton presetBypass = createChip("Bypasses (403->200)", () -> {
            resetFiltersSilently();
            signalFilterBtn.setSelected(Set.of("Bypass Detected (403/401 -> 200)"));
            severityFilterBtn.setSelected(Set.of("High"));
            applyFilter();
        });

        JButton presetCsrf = createChip("CSRF Candidates", () -> {
            resetFiltersSilently();
            signalFilterBtn.setSelected(Set.of("Method Permitted / CSRF Potential"));
            severityFilterBtn.setSelected(Set.of("Medium"));
            applyFilter();
        });

        JButton presetServerErrors = createChip("5xx Errors", () -> {
            resetFiltersSilently();
            getStatusFilterBtn.setSelected(Set.of("5xx Server Error"));
            applyFilter();
        });

        JButton presetAnomalies = createChip("All Anomalies", () -> {
            resetFiltersSilently();
            anomaliesOnlyCheckbox.setSelected(true);
            applyFilter();
        });

        presetPanel.add(presetBypass);
        presetPanel.add(presetCsrf);
        presetPanel.add(presetServerErrors);
        presetPanel.add(presetAnomalies);
        add(presetPanel);
        add(Box.createVerticalStrut(6));

        // ── 3. Multi-Select Triage Section ──
        JPanel triagePanel = new JPanel(new GridLayout(0, 2, 6, 6));
        triagePanel.setBorder(new TitledBorder("Triage Multi-Selects"));

        triagePanel.add(new JLabel("Signal / Finding:"));
        triagePanel.add(signalFilterBtn);

        triagePanel.add(new JLabel("Severity:"));
        triagePanel.add(severityFilterBtn);

        triagePanel.add(new JLabel("GET Status:"));
        triagePanel.add(getStatusFilterBtn);

        triagePanel.add(new JLabel("Content-Type:"));
        triagePanel.add(contentTypeFilterBtn);

        add(triagePanel);
        add(Box.createVerticalStrut(6));

        // ── 4. Manual Text & Search Filters ──
        JPanel manualPanel = new JPanel(new GridLayout(0, 2, 6, 6));
        manualPanel.setBorder(new TitledBorder("Host & Content Bounds"));

        manualPanel.add(new JLabel("Domain / Host:"));
        domainField.setToolTipText("Filter by host or domain (auto-sanitized)");
        domainField.getDocument().addDocumentListener((FilterUtils.SimpleDocumentListener) this::triggerDebouncedFilter);
        manualPanel.add(domainField);

        manualPanel.add(new JLabel("Min Length (B):"));
        minLengthField.getDocument().addDocumentListener((FilterUtils.SimpleDocumentListener) this::triggerDebouncedFilter);
        manualPanel.add(minLengthField);

        manualPanel.add(new JLabel("Max Length (B):"));
        maxLengthField.getDocument().addDocumentListener((FilterUtils.SimpleDocumentListener) this::triggerDebouncedFilter);
        manualPanel.add(maxLengthField);

        manualPanel.add(new JLabel("Signal Contains:"));
        evidenceSearchField.getDocument().addDocumentListener((FilterUtils.SimpleDocumentListener) this::triggerDebouncedFilter);
        manualPanel.add(evidenceSearchField);

        add(manualPanel);

        JPanel searchOptions = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        searchOptions.add(regexSearchCheckBox);
        searchOptions.add(matchCaseCheckBox);
        regexSearchCheckBox.addActionListener(e -> triggerDebouncedFilter());
        matchCaseCheckBox.addActionListener(e -> triggerDebouncedFilter());
        add(searchOptions);

        add(Box.createVerticalStrut(8));

        // ── 5. Action Buttons & Metrics ──
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton applyButton = new JButton("Apply Filters");
        applyButton.addActionListener(e -> applyFilter());
        actionRow.add(applyButton);

        JButton resetButton = new JButton("Reset Filters");
        resetButton.addActionListener(e -> resetFilters());
        actionRow.add(resetButton);
        add(actionRow);

        add(Box.createVerticalStrut(4));
        statsLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        statsLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(statsLabel);

        add(Box.createVerticalGlue());
    }

    private JButton createChip(String label, Runnable action) {
        JButton btn = new JButton(label);
        btn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        btn.setMargin(new Insets(1, 4, 1, 4));
        btn.addActionListener(e -> action.run());
        return btn;
    }

    private void triggerDebouncedFilter() {
        debounceTimer.restart();
    }

    public void updateMetrics(int total, int displayed, int pinned) {
        int pct = total > 0 ? (int) Math.round((1.0 - ((double) displayed / total)) * 100) : 0;
        statsLabel.setText(String.format("Total: %d | Displayed: %d (%d%% filtered)%s",
            total, displayed, pct, pinned > 0 ? " | Pinned: " + pinned : ""));
    }

    public void resetSmartSignatures() {
        smartFilterSignatures.clear();
    }

    public void applyFilter() {
        boolean smartEnabled = smartFilterCheckbox.isSelected();
        boolean hide405 = hideMethodNotAllowedCheckbox.isSelected();
        boolean anomaliesOnly = anomaliesOnlyCheckbox.isSelected();

        Set<String> selectedSignals = signalFilterBtn.getSelected();
        Set<String> selectedSeverities = severityFilterBtn.getSelected();
        Set<String> selectedGetStatuses = getStatusFilterBtn.getSelected();
        Set<String> selectedContentTypes = contentTypeFilterBtn.getSelected();

        String domainFilter = domainField.getText().trim();
        Integer minLen = parseInteger(minLengthField.getText());
        Integer maxLen = parseInteger(maxLengthField.getText());

        String searchQuery = evidenceSearchField.getText().trim();
        boolean isRegex = regexSearchCheckBox.isSelected();
        boolean matchCase = matchCaseCheckBox.isSelected();

        Pattern pattern = null;
        if (isRegex && !searchQuery.isEmpty()) {
            try {
                pattern = Pattern.compile(searchQuery, matchCase ? 0 : Pattern.CASE_INSENSITIVE);
            } catch (Exception ignored) {}
        }
        final Pattern finalPattern = pattern;

        filterCallback.accept(result -> {
            // 1. Hide 405 Method Not Allowed / 501 Not Implemented
            if (hide405 && (result.getStatus() == 405 || result.getStatus() == 501)) {
                return false;
            }

            // 2. Anomalies only (High / Medium)
            if (anomaliesOnly) {
                String sev = result.severity();
                if (!"High".equalsIgnoreCase(sev) && !"Medium".equalsIgnoreCase(sev)) {
                    return false;
                }
            }

            // 3. Smart Pattern Suppression
            if (smartEnabled) {
                String sig = result.getStatus() + ":" + result.getLength() + ":" + result.getContentType();
                int count = smartFilterSignatures.compute(sig, (k, v) -> v == null ? 1 : v + 1);
                if (count > 1) {
                    return false;
                }
            }

            // 4. Domain / Host filter
            if (!FilterUtils.matchesDomain(result.host(), domainFilter)) {
                return false;
            }

            // 5. GET Status Code filter
            if (!FilterUtils.matchesStatusCode(result.getStatus(), selectedGetStatuses)) {
                return false;
            }

            // 6. Content-Type filter
            if (!FilterUtils.matchesContentType(result.getContentType(), selectedContentTypes)) {
                return false;
            }

            // 7. Severity filter
            if (!selectedSeverities.isEmpty() && !selectedSeverities.contains("All Severities")) {
                boolean matchesSev = selectedSeverities.stream()
                    .anyMatch(s -> s.equalsIgnoreCase(result.severity()));
                if (!matchesSev) return false;
            }

            // 8. Signal filter
            if (!selectedSignals.isEmpty() && !selectedSignals.contains("All Signals")) {
                String resSig = result.signal().toLowerCase();
                boolean matchesSig = false;
                for (String selSig : selectedSignals) {
                    String lower = selSig.toLowerCase();
                    if (lower.contains("bypass") && resSig.contains("bypass")) matchesSig = true;
                    else if (lower.contains("csrf") && (resSig.contains("csrf") || resSig.contains("permitted"))) matchesSig = true;
                    else if (lower.contains("5xx") && (result.getStatus() >= 500 || resSig.contains("5xx"))) matchesSig = true;
                    else if (lower.contains("redirect") && (result.getStatus() >= 300 && result.getStatus() < 400)) matchesSig = true;
                    else if (lower.contains("changed") && (result.getStatus() != result.baseStatus())) matchesSig = true;
                    else if (lower.contains("405") && result.getStatus() == 405) matchesSig = true;
                }
                if (!matchesSig) return false;
            }

            // 9. Length bounds
            if (minLen != null && result.getLength() < minLen) {
                return false;
            }
            if (maxLen != null && result.getLength() > maxLen) {
                return false;
            }

            // 10. Search query in Signal / Evidence
            if (!searchQuery.isEmpty()) {
                String targetText = result.signal() + " " + result.evidence() + " " + result.url();
                if (finalPattern != null) {
                    if (!finalPattern.matcher(targetText).find()) return false;
                } else {
                    String q = matchCase ? searchQuery : searchQuery.toLowerCase();
                    String t = matchCase ? targetText : targetText.toLowerCase();
                    if (!t.contains(q)) return false;
                }
            }

            return true;
        });
    }

    private void resetFiltersSilently() {
        smartFilterCheckbox.setSelected(false);
        hideMethodNotAllowedCheckbox.setSelected(false);
        anomaliesOnlyCheckbox.setSelected(false);
        signalFilterBtn.clearSelection();
        severityFilterBtn.clearSelection();
        getStatusFilterBtn.clearSelection();
        contentTypeFilterBtn.clearSelection();
        domainField.setText("");
        minLengthField.setText("");
        maxLengthField.setText("");
        evidenceSearchField.setText("");
        regexSearchCheckBox.setSelected(false);
        matchCaseCheckBox.setSelected(false);
        resetSmartSignatures();
    }

    public void resetFilters() {
        resetFiltersSilently();
        filterCallback.accept(r -> true);
    }

    private Integer parseInteger(String text) {
        if (text == null || text.trim().isEmpty()) return null;
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
