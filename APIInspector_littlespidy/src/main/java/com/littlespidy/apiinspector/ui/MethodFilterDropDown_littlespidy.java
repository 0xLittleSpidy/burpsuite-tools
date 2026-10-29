// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.util.*;

/**
 * Multi-select dropdown button for filtering endpoints by HTTP method.
 * Follows the design patterns used in ng-auth-analyzer_littlespidy.
 */
public class MethodFilterDropDown_littlespidy extends JButton {

    private static final List<String> DEFAULT_METHODS = Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"
    );

    private final Map<String, JCheckBox> methodCheckBoxMap = new LinkedHashMap<>();
    private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
    private final JPopupMenu popupMenu = new JPopupMenu();
    private final JPanel itemsPanel = new JPanel();
    private final List<Runnable> listeners = new ArrayList<>();
    private boolean updatingProgrammatically = false;

    public MethodFilterDropDown_littlespidy() {
        super("Methods: All");
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
            for (JCheckBox cb : methodCheckBoxMap.values()) {
                cb.setSelected(selected);
            }
            updatingProgrammatically = false;
            updateButtonLabel();
            notifyListeners();
        });
        mainPopupPanel.add(selectAllCheckBox);
        mainPopupPanel.add(new JSeparator());

        itemsPanel.setLayout(new BoxLayout(itemsPanel, BoxLayout.Y_AXIS));

        ActionListener itemListener = e -> {
            if (updatingProgrammatically) {
                return;
            }
            syncSelectAllState();
            updateButtonLabel();
            notifyListeners();
        };

        for (String method : DEFAULT_METHODS) {
            JCheckBox cb = new JCheckBox(method, true);
            cb.addActionListener(itemListener);
            methodCheckBoxMap.put(method, cb);
            itemsPanel.add(cb);
        }

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

    public synchronized void registerMethod(String method) {
        if (method == null || method.trim().isEmpty()) {
            return;
        }
        String upper = method.trim().toUpperCase(Locale.ROOT);
        if (!methodCheckBoxMap.containsKey(upper)) {
            JCheckBox cb = new JCheckBox(upper, selectAllCheckBox.isSelected());
            cb.addActionListener(e -> {
                if (updatingProgrammatically) {
                    return;
                }
                syncSelectAllState();
                updateButtonLabel();
                notifyListeners();
            });
            methodCheckBoxMap.put(upper, cb);
            itemsPanel.add(cb);
            syncSelectAllState();
            updateButtonLabel();
        }
    }

    private void syncSelectAllState() {
        int selectedCount = 0;
        for (JCheckBox cb : methodCheckBoxMap.values()) {
            if (cb.isSelected()) {
                selectedCount++;
            }
        }
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(selectedCount == methodCheckBoxMap.size());
        updatingProgrammatically = false;
    }

    private void updateButtonLabel() {
        int selectedCount = 0;
        List<String> selectedMethods = new ArrayList<>();
        for (Map.Entry<String, JCheckBox> entry : methodCheckBoxMap.entrySet()) {
            if (entry.getValue().isSelected()) {
                selectedCount++;
                selectedMethods.add(entry.getKey());
            }
        }

        if (selectedCount == methodCheckBoxMap.size() && selectedCount > 0) {
            setText("Methods: All");
        } else if (selectedCount == 0) {
            setText("Methods: None");
        } else if (selectedCount <= 2) {
            setText("Methods: " + String.join(", ", selectedMethods));
        } else {
            setText("Methods: (" + selectedCount + "/" + methodCheckBoxMap.size() + ")");
        }
    }

    public boolean isMethodSelected(String method) {
        if (method == null) {
            return false;
        }
        String upper = method.trim().toUpperCase(Locale.ROOT);
        JCheckBox cb = methodCheckBoxMap.get(upper);
        if (cb != null) {
            return cb.isSelected();
        }
        // If an unregistered method is passed, check if selectAll is active
        return selectAllCheckBox.isSelected();
    }

    public Set<String> getSelectedMethods() {
        Set<String> selected = new HashSet<>();
        for (Map.Entry<String, JCheckBox> entry : methodCheckBoxMap.entrySet()) {
            if (entry.getValue().isSelected()) {
                selected.add(entry.getKey());
            }
        }
        return selected;
    }

    public void selectAll(boolean select) {
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(select);
        for (JCheckBox cb : methodCheckBoxMap.values()) {
            cb.setSelected(select);
        }
        updatingProgrammatically = false;
        updateButtonLabel();
        notifyListeners();
    }

    public synchronized void setMethodSelected(String method, boolean selected) {
        if (method == null) return;
        String upper = method.trim().toUpperCase(Locale.ROOT);
        JCheckBox cb = methodCheckBoxMap.get(upper);
        if (cb != null) {
            cb.setSelected(selected);
            syncSelectAllState();
            updateButtonLabel();
            notifyListeners();
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
            } catch (Exception ignored) {
            }
        }
    }
}
