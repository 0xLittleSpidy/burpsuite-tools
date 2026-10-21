// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.apiinspector.ui;

import com.littlespidy.apiinspector.model.ImportedCollection_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;

/**
 * Multi-select dropdown button for filtering requests by collection.
 * Follows the design patterns used in ng-auth-analyzer_littlespidy.
 */
public class CollectionFilterDropDown_littlespidy extends JButton {

    private final Map<String, JCheckBox> collectionCheckBoxMap = new LinkedHashMap<>();
    private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
    private final JPopupMenu popupMenu = new JPopupMenu();
    private final JPanel itemsPanel = new JPanel();
    private final List<Runnable> listeners = new ArrayList<>();
    private boolean updatingProgrammatically = false;

    public CollectionFilterDropDown_littlespidy() {
        super("Collections: All");
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
            for (JCheckBox cb : collectionCheckBoxMap.values()) {
                cb.setSelected(selected);
            }
            updatingProgrammatically = false;
            updateButtonLabel();
            notifyListeners();
        });
        mainPopupPanel.add(selectAllCheckBox);
        mainPopupPanel.add(new JSeparator());

        itemsPanel.setLayout(new BoxLayout(itemsPanel, BoxLayout.Y_AXIS));
        JScrollPane scrollPane = new JScrollPane(itemsPanel,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setBorder(null);
        scrollPane.setPreferredSize(new Dimension(240, 160));
        mainPopupPanel.add(scrollPane);

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

    public synchronized void updateCollections(List<ImportedCollection_littlespidy> collections) {
        if (collections == null) {
            return;
        }

        Set<String> currentIds = new HashSet<>();
        for (ImportedCollection_littlespidy c : collections) {
            currentIds.add(c.getId());
        }

        // Remove collections no longer present
        Iterator<Map.Entry<String, JCheckBox>> it = collectionCheckBoxMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, JCheckBox> entry = it.next();
            if (!currentIds.contains(entry.getKey())) {
                itemsPanel.remove(entry.getValue());
                it.remove();
            }
        }

        // Add or update existing
        ActionListener itemListener = e -> {
            if (updatingProgrammatically) {
                return;
            }
            syncSelectAllState();
            updateButtonLabel();
            notifyListeners();
        };

        boolean hadAny = !collectionCheckBoxMap.isEmpty();
        for (ImportedCollection_littlespidy c : collections) {
            String id = c.getId();
            String label = c.getName() + " (" + c.getEndpointCount() + ")";
            if (!collectionCheckBoxMap.containsKey(id)) {
                boolean defaultSelected = !hadAny || selectAllCheckBox.isSelected();
                JCheckBox cb = new JCheckBox(label, defaultSelected);
                cb.setToolTipText(c.getName());
                cb.addActionListener(itemListener);
                collectionCheckBoxMap.put(id, cb);
                itemsPanel.add(cb);
            } else {
                collectionCheckBoxMap.get(id).setText(label);
            }
        }

        itemsPanel.revalidate();
        itemsPanel.repaint();
        syncSelectAllState();
        updateButtonLabel();
    }

    private void syncSelectAllState() {
        int selectedCount = 0;
        for (JCheckBox cb : collectionCheckBoxMap.values()) {
            if (cb.isSelected()) {
                selectedCount++;
            }
        }
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(collectionCheckBoxMap.isEmpty() || selectedCount == collectionCheckBoxMap.size());
        updatingProgrammatically = false;
    }

    private void updateButtonLabel() {
        if (collectionCheckBoxMap.isEmpty()) {
            setText("Collections: All");
            return;
        }

        int selectedCount = 0;
        String singleName = null;
        for (Map.Entry<String, JCheckBox> entry : collectionCheckBoxMap.entrySet()) {
            if (entry.getValue().isSelected()) {
                selectedCount++;
                if (singleName == null) {
                    singleName = entry.getValue().getText();
                }
            }
        }

        if (selectedCount == collectionCheckBoxMap.size()) {
            setText("Collections: All");
        } else if (selectedCount == 0) {
            setText("Collections: None (0)");
        } else if (selectedCount == 1 && singleName != null) {
            String shortName = singleName.length() > 16 ? singleName.substring(0, 14) + "..." : singleName;
            setText("Collection: " + shortName);
        } else {
            setText("Collections: (" + selectedCount + "/" + collectionCheckBoxMap.size() + ")");
        }
    }

    public boolean isCollectionSelected(String collectionId) {
        if (collectionId == null) {
            return false;
        }
        if (collectionCheckBoxMap.isEmpty()) {
            return true;
        }
        JCheckBox cb = collectionCheckBoxMap.get(collectionId);
        if (cb != null) {
            return cb.isSelected();
        }
        return selectAllCheckBox.isSelected();
    }

    public Set<String> getSelectedCollectionIds() {
        Set<String> selected = new HashSet<>();
        for (Map.Entry<String, JCheckBox> entry : collectionCheckBoxMap.entrySet()) {
            if (entry.getValue().isSelected()) {
                selected.add(entry.getKey());
            }
        }
        return selected;
    }

    public void selectAll(boolean select) {
        updatingProgrammatically = true;
        selectAllCheckBox.setSelected(select);
        for (JCheckBox cb : collectionCheckBoxMap.values()) {
            cb.setSelected(select);
        }
        updatingProgrammatically = false;
        updateButtonLabel();
        notifyListeners();
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
