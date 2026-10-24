// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.ui;

import com.littlespidy.graphqlcop.model.AuditProbeType_littlespidy;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.function.Consumer;

public class MultiSelectProbeFilter_littlespidy extends JButton {
    private final Set<String> selectedProbes = new HashSet<>();
    private final JPopupMenu popupMenu = new JPopupMenu();
    private final Map<String, JCheckBoxMenuItem> checkBoxes = new LinkedHashMap<>();
    private final Consumer<Set<String>> filterChangeCallback;

    public MultiSelectProbeFilter_littlespidy(Consumer<Set<String>> filterChangeCallback) {
        super("Filter Probes (All)");
        this.filterChangeCallback = filterChangeCallback;

        // Populate with all probes
        for (AuditProbeType_littlespidy type : AuditProbeType_littlespidy.values()) {
            selectedProbes.add(type.getDisplayName());
        }

        JMenuItem selectAll = new JMenuItem("Select All");
        selectAll.addActionListener(e -> {
            for (Map.Entry<String, JCheckBoxMenuItem> entry : checkBoxes.entrySet()) {
                entry.getValue().setSelected(true);
                selectedProbes.add(entry.getKey());
            }
            updateButtonText();
            notifyCallback();
        });

        JMenuItem deselectAll = new JMenuItem("Deselect All");
        deselectAll.addActionListener(e -> {
            for (Map.Entry<String, JCheckBoxMenuItem> entry : checkBoxes.entrySet()) {
                entry.getValue().setSelected(false);
            }
            selectedProbes.clear();
            updateButtonText();
            notifyCallback();
        });

        popupMenu.add(selectAll);
        popupMenu.add(deselectAll);
        popupMenu.addSeparator();

        for (AuditProbeType_littlespidy type : AuditProbeType_littlespidy.values()) {
            String name = type.getDisplayName();
            JCheckBoxMenuItem item = new JCheckBoxMenuItem(name, true);
            checkBoxes.put(name, item);
            item.addActionListener(e -> {
                if (item.isSelected()) {
                    selectedProbes.add(name);
                } else {
                    selectedProbes.remove(name);
                }
                updateButtonText();
                notifyCallback();
            });
            popupMenu.add(item);
        }

        addActionListener(e -> {
            popupMenu.show(this, 0, getHeight());
        });
    }

    private void updateButtonText() {
        if (selectedProbes.size() == checkBoxes.size()) {
            setText("Filter Probes (All)");
        } else if (selectedProbes.isEmpty()) {
            setText("Filter Probes (None)");
        } else {
            setText("Filter Probes (" + selectedProbes.size() + " active)");
        }
    }

    private void notifyCallback() {
        if (filterChangeCallback != null) {
            filterChangeCallback.accept(new HashSet<>(selectedProbes));
        }
    }

    public boolean isProbeSelected(String probeName) {
        if (selectedProbes.isEmpty()) return false;
        if (selectedProbes.size() == checkBoxes.size()) return true;

        for (String selected : selectedProbes) {
            if (probeName.contains(selected) || selected.contains(probeName)) {
                return true;
            }
        }
        return false;
    }
}
