package com.littlespidy.inputvalidationfuzzer.ui;

import com.littlespidy.inputvalidationfuzzer.model.FuzzResult;
import com.littlespidy.inputvalidationfuzzer.model.FuzzerConfig;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Filter sidebar implementing Smart pattern suppression, manual status code & length filtering,
 * regex searches on signals and responses, and severity filters.
 *
 * @author littlespidy
 */
public class FilterPanel extends JPanel {
    private final JCheckBox smartFilterCheckbox = new JCheckBox("Enable Smart Filter (auto-hide repeated patterns)", false);
    private final JCheckBox hideNormalCheckbox = new JCheckBox("Hide Normal Responses", false);

    private final JTextField hideStatusCodesField = new JTextField();
    private final JTextField showStatusCodesField = new JTextField();
    private final JTextField minLengthField = new JTextField();
    private final JTextField maxLengthField = new JTextField();
    private final JTextField signalContainsField = new JTextField();
    private final JComboBox<String> severityCombo = new JComboBox<>(new String[]{"All", "High", "Medium", "Low", "Info"});

    private final Consumer<java.util.function.Predicate<FuzzResult>> filterCallback;
    private final Map<String, Integer> smartFilterSignatures = new ConcurrentHashMap<>();

    public FilterPanel(FuzzerConfig config, Consumer<java.util.function.Predicate<FuzzResult>> filterCallback) {
        this.filterCallback = filterCallback;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ── Smart Filter Section ──
        JPanel smartPanel = new JPanel(new GridLayout(0, 1, 4, 4));
        smartPanel.setBorder(new TitledBorder("Smart Filter"));
        smartPanel.add(smartFilterCheckbox);
        smartPanel.add(hideNormalCheckbox);
        add(smartPanel);
        add(Box.createVerticalStrut(8));

        // ── Manual Filter Section ──
        JPanel manualPanel = new JPanel(new GridLayout(0, 2, 6, 6));
        manualPanel.setBorder(new TitledBorder("Manual Filters"));

        manualPanel.add(new JLabel("Hide Status:"));
        manualPanel.add(hideStatusCodesField);
        hideStatusCodesField.setToolTipText("e.g. 404, 400, 500");

        manualPanel.add(new JLabel("Show Status:"));
        manualPanel.add(showStatusCodesField);
        showStatusCodesField.setToolTipText("e.g. 200, 500");

        manualPanel.add(new JLabel("Min Length (B):"));
        manualPanel.add(minLengthField);

        manualPanel.add(new JLabel("Max Length (B):"));
        manualPanel.add(maxLengthField);

        manualPanel.add(new JLabel("Signal Contains:"));
        manualPanel.add(signalContainsField);

        manualPanel.add(new JLabel("Severity:"));
        manualPanel.add(severityCombo);

        add(manualPanel);
        add(Box.createVerticalStrut(8));

        JButton applyButton = new JButton("Apply Filters");
        applyButton.addActionListener(e -> applyFilter());
        add(applyButton);

        JButton resetButton = new JButton("Reset Filters");
        resetButton.addActionListener(e -> resetFilters());
        add(Box.createVerticalStrut(4));
        add(resetButton);

        add(Box.createVerticalGlue());
    }

    public void resetSmartSignatures() {
        smartFilterSignatures.clear();
    }

    public void applyFilter() {
        boolean smartEnabled = smartFilterCheckbox.isSelected();
        boolean hideNormal = hideNormalCheckbox.isSelected();

        Set<Integer> hideCodes = parseStatusCodes(hideStatusCodesField.getText());
        Set<Integer> showCodes = parseStatusCodes(showStatusCodesField.getText());
        Integer minLen = parseInteger(minLengthField.getText());
        Integer maxLen = parseInteger(maxLengthField.getText());
        String signalQuery = signalContainsField.getText().trim().toLowerCase();
        String selectedSeverity = (String) severityCombo.getSelectedItem();

        filterCallback.accept(result -> {
            if (hideNormal && result.signal().startsWith("Normal")) {
                return false;
            }

            if (smartEnabled) {
                String sig = result.responseStatus() + ":" + result.responseLength() + ":" + result.responseContentType();
                int count = smartFilterSignatures.compute(sig, (k, v) -> v == null ? 1 : v + 1);
                if (count > 1) {
                    return false;
                }
            }

            if (!hideCodes.isEmpty() && hideCodes.contains(result.responseStatus())) {
                return false;
            }

            if (!showCodes.isEmpty() && !showCodes.contains(result.responseStatus())) {
                return false;
            }

            if (minLen != null && result.responseLength() < minLen) {
                return false;
            }

            if (maxLen != null && result.responseLength() > maxLen) {
                return false;
            }

            if (!signalQuery.isEmpty() && !result.signal().toLowerCase().contains(signalQuery)) {
                return false;
            }

            if (selectedSeverity != null && !selectedSeverity.equals("All")) {
                if (!selectedSeverity.equalsIgnoreCase(result.issueSeverity())) {
                    return false;
                }
            }

            return true;
        });
    }

    private void resetFilters() {
        smartFilterCheckbox.setSelected(false);
        hideNormalCheckbox.setSelected(false);
        hideStatusCodesField.setText("");
        showStatusCodesField.setText("");
        minLengthField.setText("");
        maxLengthField.setText("");
        signalContainsField.setText("");
        severityCombo.setSelectedIndex(0);
        resetSmartSignatures();
        filterCallback.accept(r -> true);
    }

    private Set<Integer> parseStatusCodes(String text) {
        Set<Integer> codes = new HashSet<>();
        if (text == null || text.trim().isEmpty()) return codes;
        for (String part : text.split("[,\\s]+")) {
            try {
                codes.add(Integer.parseInt(part.trim()));
            } catch (NumberFormatException ignored) {}
        }
        return codes;
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
