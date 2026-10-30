// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.InputValidationTestResult_littlespidy.ValidationSeverity;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Multi-select dropdown button for filtering Input Validation test outcomes by severity.
 */
public class ValidationSeverityFilterDropDown_littlespidy extends JButton {

    private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
    private final JCheckBox highCheckBox = new JCheckBox("High", true);
    private final JCheckBox mediumCheckBox = new JCheckBox("Medium", true);
    private final JCheckBox lowCheckBox = new JCheckBox("Low", true);
    private final JCheckBox infoCheckBox = new JCheckBox("Info", true);

    private final JPopupMenu popupMenu = new JPopupMenu();
    private final List<Runnable> listeners = new ArrayList<>();
    private boolean updatingProgrammatically = false;

    public ValidationSeverityFilterDropDown_littlespidy() {
        super("Severity: All");
        initUI();
    }

    private void initUI() {
        JPanel mainPopupPanel = new JPanel();
        mainPopupPanel.setLayout(new BoxLayout(mainPopupPanel, BoxLayout.Y_AXIS));
        mainPopupPanel.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        selectAllCheckBox.addActionListener(e -> {
            if (updatingProgrammatically) return;
            boolean selected = selectAllCheckBox.isSelected();
            updatingProgrammatically = true;
            highCheckBox.setSelected(selected);
            mediumCheckBox.setSelected(selected);
            lowCheckBox.setSelected(selected);
            infoCheckBox.setSelected(selected);
            updatingProgrammatically = false;
            updateButtonLabel();
            notifyListeners();
        });
        mainPopupPanel.add(selectAllCheckBox);
        mainPopupPanel.add(new JSeparator());

        ActionListener itemListener = e -> {
            if (updatingProgrammatically) return;
            syncSelectAllState();
            updateButtonLabel();
            notifyListeners();
        };

        highCheckBox.addActionListener(itemListener);
        mediumCheckBox.addActionListener(itemListener);
        lowCheckBox.addActionListener(itemListener);
        infoCheckBox.addActionListener(itemListener);

        mainPopupPanel.add(highCheckBox);
        mainPopupPanel.add(mediumCheckBox);
        mainPopupPanel.add(lowCheckBox);
        mainPopupPanel.add(infoCheckBox);

        popupMenu.add(mainPopupPanel);

        addActionListener(e -> {
            if (popupMenu.isVisible()) {
                popupMenu.setVisible(false);
            } else {
                popupMenu.show(this, 0, getHeight());
            }
        });
        updateButtonLabel();
    }

    public boolean matches(ValidationSeverity sev) {
        if (sev == null) return true;
        switch (sev) {
            case HIGH: return highCheckBox.isSelected();
            case MEDIUM: return mediumCheckBox.isSelected();
            case LOW: return lowCheckBox.isSelected();
            case INFO: return infoCheckBox.isSelected();
            default: return true;
        }
    }

    public void addFilterChangeListener(Runnable listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    private void notifyListeners() {
        for (Runnable r : listeners) {
            try {
                r.run();
            } catch (Exception ignored) {}
        }
    }

    private void syncSelectAllState() {
        boolean all = highCheckBox.isSelected() && mediumCheckBox.isSelected()
                && lowCheckBox.isSelected() && infoCheckBox.isSelected();
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(all);
        updatingProgrammatically = false;
    }

    private void updateButtonLabel() {
        int count = 0;
        if (highCheckBox.isSelected()) count++;
        if (mediumCheckBox.isSelected()) count++;
        if (lowCheckBox.isSelected()) count++;
        if (infoCheckBox.isSelected()) count++;

        if (count == 4) {
            setText("Severity: All");
        } else if (count == 0) {
            setText("Severity: None (0)");
        } else {
            setText("Severity: (" + count + "/4)");
        }
    }
}
