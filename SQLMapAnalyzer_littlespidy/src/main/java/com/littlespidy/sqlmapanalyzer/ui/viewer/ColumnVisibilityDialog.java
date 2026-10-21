// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.viewer;

import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Dialog allowing users to select which columns to display in the table data viewer.
 * Plain ASCII text only.
 */
public class ColumnVisibilityDialog extends JDialog {

    private final List<JCheckBox> checkBoxes = new ArrayList<>();
    private final Consumer<List<String>> onApply;

    public ColumnVisibilityDialog(Window owner, List<String> allColumns, List<String> currentlyVisible, Consumer<List<String>> onApply) {
        super(owner, "Select Visible Columns", ModalityType.APPLICATION_MODAL);
        this.onApply = onApply;

        setLayout(new BorderLayout(10, 10));
        setSize(360, 420);
        setLocationRelativeTo(owner);

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(new EmptyBorder(10, 15, 10, 15));

        Set<String> visibleSet = new HashSet<>(currentlyVisible != null ? currentlyVisible : allColumns);

        for (String col : allColumns) {
            JCheckBox cb = new JCheckBox(col, visibleSet.contains(col));
            checkBoxes.add(cb);
            contentPanel.add(cb);
            contentPanel.add(Box.createVerticalStrut(4));
        }

        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);

        // Action panel
        JPanel actionPanel = new JPanel(new BorderLayout(5, 5));
        actionPanel.setBorder(new EmptyBorder(5, 10, 10, 10));

        JPanel togglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JButton btnSelectAll = SwingUtils.createStyledButton("Select All");
        btnSelectAll.addActionListener(e -> {
            for (JCheckBox cb : checkBoxes) cb.setSelected(true);
        });
        JButton btnDeselectAll = SwingUtils.createStyledButton("Deselect All");
        btnDeselectAll.addActionListener(e -> {
            for (JCheckBox cb : checkBoxes) cb.setSelected(false);
        });
        togglePanel.add(btnSelectAll);
        togglePanel.add(btnDeselectAll);

        JPanel closePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        JButton btnApply = SwingUtils.createStyledButton("Apply");
        btnApply.setFont(btnApply.getFont().deriveFont(Font.BOLD));
        btnApply.addActionListener(e -> applySelection());

        JButton btnCancel = SwingUtils.createStyledButton("Cancel");
        btnCancel.addActionListener(e -> dispose());

        closePanel.add(btnApply);
        closePanel.add(btnCancel);

        actionPanel.add(togglePanel, BorderLayout.WEST);
        actionPanel.add(closePanel, BorderLayout.EAST);

        add(actionPanel, BorderLayout.SOUTH);
    }

    private void applySelection() {
        List<String> selected = new ArrayList<>();
        for (JCheckBox cb : checkBoxes) {
            if (cb.isSelected()) {
                selected.add(cb.getText());
            }
        }
        if (selected.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select at least one column to display.", "Selection Required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (onApply != null) {
            onApply.accept(selected);
        }
        dispose();
    }
}
