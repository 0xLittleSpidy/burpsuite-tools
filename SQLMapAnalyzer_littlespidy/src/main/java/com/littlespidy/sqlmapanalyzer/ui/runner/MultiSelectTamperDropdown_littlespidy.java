// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Multi-select dropdown component for SQLMap tamper scripts with live search,
 * scrollable checklist, and manual text editing support.
 * Plain ASCII text only.
 */
public class MultiSelectTamperDropdown_littlespidy extends JPanel {

    private static final String[] KNOWN_TAMPER_SCRIPTS = {
            "apostrophemask",
            "apostrophenullencode",
            "base64encode",
            "between",
            "bluecoat",
            "chardoubleencode",
            "charencode",
            "charunicodeencode",
            "concat2concatws",
            "equaltolike",
            "greatest",
            "halfversionedmorekeywords",
            "ifnull2ifisnull",
            "lowercase",
            "modsecurityversioned",
            "modsecurityzeroversioned",
            "multiplespaces",
            "nonrecursivereplacement",
            "percentage",
            "randomcase",
            "randomcomments",
            "securesphere",
            "space2comment",
            "space2dash",
            "space2hash",
            "space2morehash",
            "space2plus",
            "space2randomblank",
            "unionalltounion",
            "unmagicquotes",
            "versionedkeywords",
            "versionedmorekeywords"
    };

    private final JTextField textField;
    private final JButton btnDropdown;
    private final Set<String> selectedScripts = new LinkedHashSet<>();
    private final Map<String, JCheckBox> checkBoxes = new LinkedHashMap<>();
    private boolean internalUpdate = false;

    public MultiSelectTamperDropdown_littlespidy() {
        setLayout(new BorderLayout(2, 0));

        textField = new JTextField();
        textField.setToolTipText("Comma-separated tamper scripts (e.g. space2comment,between,randomcase)");
        textField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { onTextChanged(); }
            @Override
            public void removeUpdate(DocumentEvent e) { onTextChanged(); }
            @Override
            public void changedUpdate(DocumentEvent e) { onTextChanged(); }
        });

        btnDropdown = SwingUtils.createStyledButton("v");
        btnDropdown.setFont(new Font(Font.MONOSPACED, Font.BOLD, 10));
        btnDropdown.setMargin(new Insets(1, 4, 1, 4));
        btnDropdown.setToolTipText("Select tamper scripts from list");
        btnDropdown.addActionListener(e -> showPopup());

        add(textField, BorderLayout.CENTER);
        add(btnDropdown, BorderLayout.EAST);
    }

    private void onTextChanged() {
        if (internalUpdate) return;
        selectedScripts.clear();
        String raw = textField.getText().trim();
        if (!raw.isBlank()) {
            String[] parts = raw.split(",");
            for (String p : parts) {
                String clean = p.trim().toLowerCase();
                if (!clean.isEmpty()) {
                    selectedScripts.add(clean);
                }
            }
        }
    }

    private void showPopup() {
        JPopupMenu popup = new JPopupMenu();
        popup.setLayout(new BorderLayout());
        popup.setBorder(BorderFactory.createLineBorder(Color.GRAY));

        JPanel topBar = new JPanel(new BorderLayout(4, 2));
        topBar.setBorder(new EmptyBorder(4, 4, 4, 4));

        JTextField searchField = new JTextField();
        searchField.putClientProperty("JTextField.placeholderText", "Search tamper scripts...");
        searchField.setPreferredSize(new Dimension(160, 22));

        JButton btnClear = SwingUtils.createStyledButton("Clear");
        btnClear.addActionListener(e -> {
            selectedScripts.clear();
            updateFromCheckboxes();
            popup.repaint();
        });

        JButton btnDone = SwingUtils.createStyledButton("Done");
        btnDone.addActionListener(e -> popup.setVisible(false));

        JPanel btnFlow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
        btnFlow.add(btnClear);
        btnFlow.add(btnDone);

        topBar.add(searchField, BorderLayout.CENTER);
        topBar.add(btnFlow, BorderLayout.EAST);
        popup.add(topBar, BorderLayout.NORTH);

        // Checklist panel
        JPanel checkListPanel = new JPanel();
        checkListPanel.setLayout(new BoxLayout(checkListPanel, BoxLayout.Y_AXIS));
        checkListPanel.setBorder(new EmptyBorder(2, 6, 4, 6));

        checkBoxes.clear();
        for (String script : KNOWN_TAMPER_SCRIPTS) {
            JCheckBox cb = new JCheckBox(script);
            cb.setSelected(selectedScripts.contains(script.toLowerCase()));
            cb.addActionListener(e -> {
                if (cb.isSelected()) {
                    selectedScripts.add(script.toLowerCase());
                } else {
                    selectedScripts.remove(script.toLowerCase());
                }
                updateFromCheckboxes();
            });
            checkBoxes.put(script, cb);
            checkListPanel.add(cb);
        }

        // Live search filtering
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            private void filter() {
                String q = searchField.getText().trim().toLowerCase();
                checkListPanel.removeAll();
                for (String script : KNOWN_TAMPER_SCRIPTS) {
                    if (q.isEmpty() || script.toLowerCase().contains(q)) {
                        checkListPanel.add(checkBoxes.get(script));
                    }
                }
                checkListPanel.revalidate();
                checkListPanel.repaint();
            }
            @Override public void insertUpdate(DocumentEvent e) { filter(); }
            @Override public void removeUpdate(DocumentEvent e) { filter(); }
            @Override public void changedUpdate(DocumentEvent e) { filter(); }
        });

        JScrollPane scrollPane = new JScrollPane(checkListPanel);
        scrollPane.setPreferredSize(new Dimension(300, 240));
        scrollPane.getVerticalScrollBar().setUnitIncrement(12);
        popup.add(scrollPane, BorderLayout.CENTER);

        popup.show(this, 0, getHeight());
        searchField.requestFocusInWindow();
    }

    private void updateFromCheckboxes() {
        internalUpdate = true;
        try {
            StringBuilder sb = new StringBuilder();
            for (String s : selectedScripts) {
                if (!sb.isEmpty()) sb.append(",");
                sb.append(s);
            }
            textField.setText(sb.toString());
            // Sync visible checkboxes
            for (Map.Entry<String, JCheckBox> entry : checkBoxes.entrySet()) {
                entry.getValue().setSelected(selectedScripts.contains(entry.getKey().toLowerCase()));
            }
        } finally {
            internalUpdate = false;
        }
    }

    public String getText() {
        return textField.getText().trim();
    }

    public void setText(String text) {
        internalUpdate = true;
        try {
            textField.setText(text != null ? text : "");
            selectedScripts.clear();
            if (text != null && !text.isBlank()) {
                for (String part : text.split(",")) {
                    String clean = part.trim().toLowerCase();
                    if (!clean.isEmpty()) {
                        selectedScripts.add(clean);
                    }
                }
            }
        } finally {
            internalUpdate = false;
        }
    }
}
