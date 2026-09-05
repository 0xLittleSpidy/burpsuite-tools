// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * A reusable toolbar button that opens a popup panel containing a list of
 * checkboxes so the user can select multiple filter values at once.
 */
public class MultiSelectFilterButton extends JButton {

    private final String label;
    private final List<String> options;
    private final Map<String, JCheckBox> checkBoxMap = new LinkedHashMap<>();
    private final Consumer<Set<String>> onChange;

    public MultiSelectFilterButton(String label, List<String> options, Consumer<Set<String>> onChange) {
        super(label + " \u25be");
        this.label = label;
        this.options = new ArrayList<>(options);
        this.onChange = onChange;
        buildCheckBoxes();
        addActionListener(e -> showPopup());
    }

    public Set<String> getSelected() {
        Set<String> result = new LinkedHashSet<>();
        for (Map.Entry<String, JCheckBox> entry : checkBoxMap.entrySet()) {
            if (entry.getValue().isSelected() && !isAllSentinel(entry.getKey())) {
                result.add(entry.getKey());
            }
        }
        return result;
    }

    public boolean isAllSelected() {
        return getSelected().isEmpty();
    }

    public void clearSelection() {
        for (JCheckBox cb : checkBoxMap.values()) {
            cb.setSelected(false);
        }
        updateButtonText();
    }

    private void buildCheckBoxes() {
        for (String opt : options) {
            JCheckBox cb = new JCheckBox(opt);
            checkBoxMap.put(opt, cb);
        }
    }

    private boolean isAllSentinel(String key) {
        if (options.isEmpty()) return false;
        return key.equals(options.get(0)) && key.toLowerCase().startsWith("all");
    }

    private void showPopup() {
        JPopupMenu popup = new JPopupMenu();
        popup.setLayout(new BorderLayout(4, 4));

        JPanel listPanel = new JPanel(new GridLayout(0, 1, 2, 2));
        listPanel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        for (Map.Entry<String, JCheckBox> entry : checkBoxMap.entrySet()) {
            String key = entry.getKey();
            JCheckBox cb = entry.getValue();

            if (isAllSentinel(key)) {
                cb.setText("Select All");
                for (ActionListener al : cb.getActionListeners()) cb.removeActionListener(al);
                cb.addActionListener(e -> {
                    boolean checked = cb.isSelected();
                    for (Map.Entry<String, JCheckBox> inner : checkBoxMap.entrySet()) {
                        if (!isAllSentinel(inner.getKey())) inner.getValue().setSelected(checked);
                    }
                    updateButtonText();
                    fireOnChange();
                });
            } else {
                for (ActionListener al : cb.getActionListeners()) cb.removeActionListener(al);
                cb.addActionListener(e -> {
                    JCheckBox allCb = checkBoxMap.get(options.get(0));
                    if (allCb != null && isAllSentinel(options.get(0))) {
                        allCb.setSelected(allOptionsChecked());
                    }
                    updateButtonText();
                    fireOnChange();
                });
            }

            listPanel.add(cb);
        }

        JScrollPane scroll = new JScrollPane(listPanel);
        scroll.setPreferredSize(new Dimension(220, Math.min(options.size() * 28 + 16, 300)));
        scroll.setBorder(BorderFactory.createEmptyBorder());
        popup.add(scroll, BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
        JButton clearBtn = new JButton("Clear");
        clearBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        clearBtn.addActionListener(e -> {
            clearSelection();
            fireOnChange();
            popup.setVisible(false);
        });
        btnRow.add(clearBtn);
        popup.add(btnRow, BorderLayout.SOUTH);

        popup.show(this, 0, getHeight());
    }

    private boolean allOptionsChecked() {
        for (Map.Entry<String, JCheckBox> entry : checkBoxMap.entrySet()) {
            if (!isAllSentinel(entry.getKey()) && !entry.getValue().isSelected()) {
                return false;
            }
        }
        return true;
    }

    private void updateButtonText() {
        Set<String> sel = getSelected();
        if (sel.isEmpty()) {
            setText(label + " \u25be");
        } else if (sel.size() == 1) {
            setText(label + ": " + sel.iterator().next() + " \u25be");
        } else {
            setText(label + " (" + sel.size() + ") \u25be");
        }
    }

    private void fireOnChange() {
        if (onChange != null) {
            onChange.accept(getSelected());
        }
    }
}
