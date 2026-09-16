// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * A reusable toolbar button that opens a popup panel containing a list of
 * checkboxes so the user can select multiple filter values at once.
 *
 * <p>Usage:
 * <pre>
 *   MultiSelectFilterButton btn = new MultiSelectFilterButton(
 *       "Technique", List.of("All Techniques", "LinkFinder", "Namespace / URL"), onChange -> refreshView());
 *   toolbar.add(btn);
 *   // Retrieve selected: btn.getSelected()  ->  Set&lt;String&gt;
 * </pre>
 *
 * @author littlespidy
 */
public class MultiSelectFilterButton extends JButton {

    private final String label;
    private final List<String> options;
    private final Map<String, JCheckBox> checkBoxMap = new LinkedHashMap<>();
    private final Consumer<Set<String>> onChange;

    /**
     * @param label    Displayed on the button face, e.g. "Technique ▾"
     * @param options  The selectable items (first item treated as "All / clear" sentinel if it starts with "All")
     * @param onChange Callback fired whenever the selection changes
     */
    public MultiSelectFilterButton(String label, List<String> options, Consumer<Set<String>> onChange) {
        super(label + " \u25be");
        this.label    = label;
        this.options  = new ArrayList<>(options);
        this.onChange = onChange;
        buildCheckBoxes();
        addActionListener(e -> showPopup());
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /** Returns a snapshot of currently checked options (excluding the "All" sentinel). */
    public synchronized Set<String> getSelected() {
        Set<String> result = new LinkedHashSet<>();
        for (Map.Entry<String, JCheckBox> entry : checkBoxMap.entrySet()) {
            if (entry.getValue().isSelected() && !isAllSentinel(entry.getKey())) {
                result.add(entry.getKey());
            }
        }
        return result;
    }

    /** Returns true if all items are checked or none are checked (pass-all state). */
    public synchronized boolean isAllSelected() {
        return allOptionsChecked() || getSelected().isEmpty();
    }

    /** Programmatically check all items. */
    public synchronized void selectAll() {
        for (JCheckBox cb : checkBoxMap.values()) cb.setSelected(true);
        updateButtonText();
    }

    /** Programmatically reset to "all cleared" (pass-all) state. */
    public synchronized void clearSelection() {
        for (JCheckBox cb : checkBoxMap.values()) cb.setSelected(false);
        updateButtonText();
    }

    /** Dynamically updates selectable options, preserving selection or defaulting to all selected. */
    public synchronized void setOptions(Collection<String> newOptions, boolean selectAllByDefault) {
        Set<String> currentlySelected = getSelected();
        boolean wasAllOrEmpty = currentlySelected.isEmpty() || isAllSelected();

        options.clear();
        checkBoxMap.clear();

        if (newOptions != null) {
            options.addAll(newOptions);
        }

        buildCheckBoxes();

        if (selectAllByDefault || wasAllOrEmpty) {
            for (JCheckBox cb : checkBoxMap.values()) {
                cb.setSelected(true);
            }
        } else {
            boolean anySelected = false;
            for (Map.Entry<String, JCheckBox> entry : checkBoxMap.entrySet()) {
                if (!isAllSentinel(entry.getKey()) && currentlySelected.contains(entry.getKey())) {
                    entry.getValue().setSelected(true);
                    anySelected = true;
                }
            }
            if (!anySelected) {
                for (JCheckBox cb : checkBoxMap.values()) {
                    cb.setSelected(true);
                }
            } else {
                JCheckBox allCb = options.isEmpty() ? null : checkBoxMap.get(options.get(0));
                if (allCb != null && isAllSentinel(options.get(0))) {
                    allCb.setSelected(allOptionsChecked());
                }
            }
        }

        updateButtonText();
    }

    /** Helper to check if a host matches a set of selected domains (exact or subdomain). */
    public static boolean matchesDomain(String host, Set<String> selectedDomains) {
        if (selectedDomains == null || selectedDomains.isEmpty()) return true;
        if (host == null || host.isBlank()) return false;
        String cleanHost = host.trim().toLowerCase();
        int colonIdx = cleanHost.indexOf(':');
        if (colonIdx != -1) {
            cleanHost = cleanHost.substring(0, colonIdx);
        }

        for (String d : selectedDomains) {
            if ("All Domains".equalsIgnoreCase(d) || "All".equalsIgnoreCase(d)) return true;
            String cleanDomain = d.trim().toLowerCase();
            int dColon = cleanDomain.indexOf(':');
            if (dColon != -1) {
                cleanDomain = cleanDomain.substring(0, dColon);
            }
            if (cleanHost.equals(cleanDomain) || cleanHost.endsWith("." + cleanDomain)) {
                return true;
            }
        }
        return false;
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    private void buildCheckBoxes() {
        for (String opt : options) {
            checkBoxMap.put(opt, new JCheckBox(opt));
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
                        inner.getValue().setSelected(checked);
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
        scroll.setPreferredSize(new Dimension(240, Math.min(options.size() * 28 + 16, 320)));
        scroll.setBorder(BorderFactory.createEmptyBorder());
        popup.add(scroll, BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        selectAllBtn.addActionListener(e -> {
            selectAll();
            fireOnChange();
        });
        btnRow.add(selectAllBtn);

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

    public synchronized boolean allOptionsChecked() {
        for (Map.Entry<String, JCheckBox> e : checkBoxMap.entrySet()) {
            if (!isAllSentinel(e.getKey()) && !e.getValue().isSelected()) return false;
        }
        return true;
    }

    private synchronized void updateButtonText() {
        Set<String> sel = getSelected();
        if (sel.isEmpty() || allOptionsChecked()) {
            setText(label + " \u25be");
        } else if (sel.size() == 1) {
            setText(label + ": " + sel.iterator().next() + " \u25be");
        } else {
            setText(label + ": " + sel.size() + " selected \u25be");
        }
    }

    private void fireOnChange() {
        if (onChange != null) onChange.accept(getSelected());
    }
}
