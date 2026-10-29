// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Multi-select dropdown button for dynamically filtering authentication test results
 * by classification: True Positive, False Positive, and Unclassified.
 */
public class ClassificationFilterDropDown_littlespidy extends JButton {

    private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
    private final JCheckBox tpCheckBox = new JCheckBox("True Positive", true);
    private final JCheckBox fpCheckBox = new JCheckBox("False Positive", true);
    private final JCheckBox unclassifiedCheckBox = new JCheckBox("Unclassified", true);

    private final JPopupMenu popupMenu = new JPopupMenu();
    private final List<Runnable> listeners = new ArrayList<>();
    private boolean updatingProgrammatically = false;

    public ClassificationFilterDropDown_littlespidy() {
        super("Classification: All");
        initUI();
    }

    private void initUI() {
        JPanel mainPopupPanel = new JPanel();
        mainPopupPanel.setLayout(new BoxLayout(mainPopupPanel, BoxLayout.Y_AXIS));
        mainPopupPanel.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        selectAllCheckBox.addActionListener(e -> {
            if (updatingProgrammatically) {
                return;
            }
            boolean selected = selectAllCheckBox.isSelected();
            updatingProgrammatically = true;
            tpCheckBox.setSelected(selected);
            fpCheckBox.setSelected(selected);
            unclassifiedCheckBox.setSelected(selected);
            updatingProgrammatically = false;
            updateButtonLabel();
            notifyListeners();
        });
        mainPopupPanel.add(selectAllCheckBox);
        mainPopupPanel.add(new JSeparator());

        JPanel itemsPanel = new JPanel();
        itemsPanel.setLayout(new BoxLayout(itemsPanel, BoxLayout.Y_AXIS));

        ActionListener itemListener = e -> {
            if (updatingProgrammatically) {
                return;
            }
            updatingProgrammatically = true;
            boolean allChecked = tpCheckBox.isSelected()
                    && fpCheckBox.isSelected()
                    && unclassifiedCheckBox.isSelected();
            selectAllCheckBox.setSelected(allChecked);
            updatingProgrammatically = false;
            updateButtonLabel();
            notifyListeners();
        };

        tpCheckBox.addActionListener(itemListener);
        fpCheckBox.addActionListener(itemListener);
        unclassifiedCheckBox.addActionListener(itemListener);

        itemsPanel.add(tpCheckBox);
        itemsPanel.add(fpCheckBox);
        itemsPanel.add(unclassifiedCheckBox);

        mainPopupPanel.add(itemsPanel);
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

    private void updateButtonLabel() {
        int total = 3;
        int count = 0;
        List<String> names = new ArrayList<>();
        if (tpCheckBox.isSelected()) {
            count++;
            names.add("TP");
        }
        if (fpCheckBox.isSelected()) {
            count++;
            names.add("FP");
        }
        if (unclassifiedCheckBox.isSelected()) {
            count++;
            names.add("Unclassified");
        }

        if (count == total) {
            setText("Classification: All");
        } else if (count == 0) {
            setText("Classification: None");
        } else {
            setText("Classification: " + String.join(", ", names));
        }
    }

    public boolean matches(AuthTestingTab_littlespidy.EndpointResultRow_littlespidy row) {
        if (row == null) {
            return false;
        }
        return matchesClassification(row.getClassification());
    }

    public boolean matchesClassification(String classification) {
        if ("TRUE_POSITIVE".equalsIgnoreCase(classification)) {
            return tpCheckBox.isSelected();
        } else if ("FALSE_POSITIVE".equalsIgnoreCase(classification)) {
            return fpCheckBox.isSelected();
        } else {
            return unclassifiedCheckBox.isSelected();
        }
    }

    public boolean isTruePositiveSelected() {
        return tpCheckBox.isSelected();
    }

    public boolean isFalsePositiveSelected() {
        return fpCheckBox.isSelected();
    }

    public boolean isUnclassifiedSelected() {
        return unclassifiedCheckBox.isSelected();
    }

    public void addFilterChangeListener(Runnable listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    private void notifyListeners() {
        for (Runnable r : new ArrayList<>(listeners)) {
            try {
                r.run();
            } catch (Exception ignored) {
            }
        }
    }
}
