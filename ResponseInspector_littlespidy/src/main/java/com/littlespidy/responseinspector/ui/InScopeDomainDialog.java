// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.responseinspector.ui;

import com.littlespidy.responseinspector.model.InScopeDomainManager;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Interactive dialog allowing users to view, search, and select/deselect specific in-scope domains.
 */
public class InScopeDomainDialog extends JDialog {

    private final InScopeDomainManager domainManager;
    private final Runnable onApplyCallback;
    private final Map<String, JCheckBox> checkBoxMap = new LinkedHashMap<>();
    private final JPanel listPanel;
    private final JTextField searchField;
    private final JLabel countLabel;

    public InScopeDomainDialog(Frame parent, InScopeDomainManager domainManager, Runnable onApplyCallback) {
        super(parent, "Select In-Scope Domains", true);
        this.domainManager = domainManager;
        this.onApplyCallback = onApplyCallback;

        setLayout(new BorderLayout(8, 8));
        setSize(480, 460);
        setLocationRelativeTo(parent);

        // Header
        JPanel headerPanel = new JPanel(new BorderLayout(4, 6));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 12, 4, 12));

        JLabel titleLabel = new JLabel("In-Scope Target Domains");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        JLabel descLabel = new JLabel("<html>Select which in-scope domains to include in analysis and findings tables.<br>Unchecked domains will be hidden from the view.</html>");
        descLabel.setForeground(Color.GRAY);

        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descLabel, BorderLayout.SOUTH);
        add(headerPanel, BorderLayout.NORTH);

        // Filter / Search Bar
        JPanel searchBarPanel = new JPanel(new BorderLayout(6, 4));
        searchBarPanel.setBorder(BorderFactory.createEmptyBorder(0, 12, 4, 12));
        searchBarPanel.add(new JLabel("Filter domains:"), BorderLayout.WEST);
        searchField = new JTextField();
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { filterList(); }
            @Override public void removeUpdate(DocumentEvent e) { filterList(); }
            @Override public void changedUpdate(DocumentEvent e) { filterList(); }
        });
        searchBarPanel.add(searchField, BorderLayout.CENTER);

        JPanel selectButtonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.addActionListener(e -> setAllChecked(true));
        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.addActionListener(e -> setAllChecked(false));
        selectButtonsPanel.add(selectAllBtn);
        selectButtonsPanel.add(deselectAllBtn);
        searchBarPanel.add(selectButtonsPanel, BorderLayout.EAST);

        // Center Domain List
        listPanel = new JPanel();
        listPanel.setLayout(new BoxLayout(listPanel, BoxLayout.Y_AXIS));
        listPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        buildDomainCheckboxes();

        JScrollPane scrollPane = new JScrollPane(listPanel);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Available Domains"));

        JPanel centerPanel = new JPanel(new BorderLayout(4, 4));
        centerPanel.setBorder(BorderFactory.createEmptyBorder(0, 12, 4, 12));
        centerPanel.add(searchBarPanel, BorderLayout.NORTH);
        centerPanel.add(scrollPane, BorderLayout.CENTER);

        countLabel = new JLabel(getCountText());
        centerPanel.add(countLabel, BorderLayout.SOUTH);

        add(centerPanel, BorderLayout.CENTER);

        // Footer
        JPanel footerPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        footerPanel.setBorder(BorderFactory.createEmptyBorder(4, 12, 10, 12));

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        JButton applyBtn = new JButton("Apply Selection");
        applyBtn.setFont(applyBtn.getFont().deriveFont(Font.BOLD));
        applyBtn.addActionListener(e -> {
            applySelection();
            dispose();
        });

        footerPanel.add(cancelBtn);
        footerPanel.add(applyBtn);
        add(footerPanel, BorderLayout.SOUTH);
    }

    private void buildDomainCheckboxes() {
        listPanel.removeAll();
        checkBoxMap.clear();

        Set<String> allDomains = domainManager.getAllDomains();
        Set<String> selectedDomains = domainManager.getSelectedDomains();
        boolean allSelected = domainManager.isAllSelected();

        if (allDomains.isEmpty()) {
            JLabel emptyLabel = new JLabel("<html><i>No in-scope domains discovered yet.<br>Click 'Load Proxy History' to ingest traffic snapshot.</i></html>");
            emptyLabel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
            listPanel.add(emptyLabel);
            return;
        }

        for (String domain : allDomains) {
            int count = domainManager.getFindingCount(domain);
            String label = domain + (count > 0 ? "  (" + count + " findings)" : "");
            JCheckBox cb = new JCheckBox(label);
            cb.setSelected(allSelected || selectedDomains.contains(domain));
            cb.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            cb.addActionListener(e -> updateCountLabel());
            checkBoxMap.put(domain, cb);
            listPanel.add(cb);
        }

        listPanel.revalidate();
        listPanel.repaint();
    }

    private void filterList() {
        String filter = searchField.getText().trim().toLowerCase();
        for (Map.Entry<String, JCheckBox> entry : checkBoxMap.entrySet()) {
            boolean visible = filter.isEmpty() || entry.getKey().toLowerCase().contains(filter);
            entry.getValue().setVisible(visible);
        }
        listPanel.revalidate();
        listPanel.repaint();
    }

    private void setAllChecked(boolean checked) {
        for (JCheckBox cb : checkBoxMap.values()) {
            if (cb.isVisible()) {
                cb.setSelected(checked);
            }
        }
        updateCountLabel();
    }

    private void updateCountLabel() {
        countLabel.setText(getCountText());
    }

    private String getCountText() {
        long checked = checkBoxMap.values().stream().filter(AbstractButton::isSelected).count();
        return "Selected: " + checked + " / " + checkBoxMap.size() + " domains";
    }

    private void applySelection() {
        Set<String> newSelected = new HashSet<>();
        for (Map.Entry<String, JCheckBox> entry : checkBoxMap.entrySet()) {
            if (entry.getValue().isSelected()) {
                newSelected.add(entry.getKey());
            }
        }
        domainManager.setSelectedDomains(newSelected);
        if (onApplyCallback != null) {
            onApplyCallback.run();
        }
    }
}
