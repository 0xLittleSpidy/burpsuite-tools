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
 * Multi-select dropdown component for selecting HTTP request headers (Cookie, Authorization, etc.)
 * with live search, scrollable checklist, and manual editing support.
 * Plain ASCII text only.
 */
public class MultiSelectHeaderDropdown_littlespidy extends JPanel {

    private final JTextField textField;
    private final JButton btnDropdown;
    private final Map<String, String> requestHeaders = new LinkedHashMap<>();
    private final Set<String> selectedHeaders = new LinkedHashSet<>();
    private final Map<String, JCheckBox> checkBoxes = new LinkedHashMap<>();
    private boolean internalUpdate = false;
    private Runnable onSelectionChanged;

    public MultiSelectHeaderDropdown_littlespidy() {
        setLayout(new BorderLayout(2, 0));

        textField = new JTextField();
        textField.setToolTipText("Selected HTTP headers to pass to SQLMap (e.g. Cookie, Authorization)");
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
        btnDropdown.setToolTipText("Select headers from request");
        btnDropdown.addActionListener(e -> showPopup());

        add(textField, BorderLayout.CENTER);
        add(btnDropdown, BorderLayout.EAST);
    }

    public void setOnSelectionChanged(Runnable callback) {
        this.onSelectionChanged = callback;
    }

    public void setRequestHeaders(Map<String, String> headers) {
        this.requestHeaders.clear();
        if (headers != null) {
            this.requestHeaders.putAll(headers);
        }
        updateTextFieldFromSelection();
    }

    public Map<String, String> getRequestHeaders() {
        return Collections.unmodifiableMap(requestHeaders);
    }

    private void onTextChanged() {
        if (internalUpdate) return;
        selectedHeaders.clear();
        String raw = textField.getText().trim();
        if (!raw.isBlank()) {
            String[] parts = raw.split(",");
            for (String p : parts) {
                String clean = p.trim();
                if (!clean.isEmpty()) {
                    String matchedKey = findMatchingHeaderKey(clean);
                    selectedHeaders.add(matchedKey != null ? matchedKey : clean);
                }
            }
        }
        if (onSelectionChanged != null) {
            onSelectionChanged.run();
        }
    }

    private String findMatchingHeaderKey(String name) {
        for (String k : requestHeaders.keySet()) {
            if (k.equalsIgnoreCase(name)) {
                return k;
            }
        }
        return null;
    }

    private boolean isHeaderSelected(String headerName) {
        for (String s : selectedHeaders) {
            if (s.equalsIgnoreCase(headerName)) {
                return true;
            }
        }
        return false;
    }

    private void removeHeaderSelection(String headerName) {
        selectedHeaders.removeIf(s -> s.equalsIgnoreCase(headerName));
    }

    private void showPopup() {
        JPopupMenu popup = new JPopupMenu();
        popup.setLayout(new BorderLayout());
        popup.setBorder(BorderFactory.createLineBorder(Color.GRAY));

        JPanel topBar = new JPanel(new BorderLayout(4, 2));
        topBar.setBorder(new EmptyBorder(4, 4, 4, 4));

        JTextField searchField = new JTextField();
        searchField.putClientProperty("JTextField.placeholderText", "Search headers...");
        searchField.setPreferredSize(new Dimension(160, 22));

        JButton btnSelectAll = SwingUtils.createStyledButton("Select All");
        btnSelectAll.addActionListener(e -> {
            selectedHeaders.clear();
            selectedHeaders.addAll(requestHeaders.keySet());
            updateFromCheckboxes();
            popup.repaint();
        });

        JButton btnClear = SwingUtils.createStyledButton("Clear");
        btnClear.addActionListener(e -> {
            selectedHeaders.clear();
            updateFromCheckboxes();
            popup.repaint();
        });

        JButton btnDone = SwingUtils.createStyledButton("Done");
        btnDone.addActionListener(e -> popup.setVisible(false));

        JPanel btnFlow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
        btnFlow.add(btnSelectAll);
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

        if (requestHeaders.isEmpty()) {
            JLabel emptyLbl = new JLabel("(No headers detected in request)");
            emptyLbl.setFont(emptyLbl.getFont().deriveFont(Font.ITALIC, 11));
            emptyLbl.setForeground(Color.GRAY);
            checkListPanel.add(emptyLbl);
        } else {
            for (Map.Entry<String, String> entry : requestHeaders.entrySet()) {
                String headerName = entry.getKey();
                String headerVal = entry.getValue();

                String previewVal = headerVal != null ? headerVal.trim() : "";
                if (previewVal.length() > 35) {
                    previewVal = previewVal.substring(0, 32) + "...";
                }

                String labelText = headerName + (previewVal.isEmpty() ? "" : ": " + previewVal);
                JCheckBox cb = new JCheckBox(labelText);
                cb.setToolTipText(headerName + ": " + headerVal);
                cb.setSelected(isHeaderSelected(headerName));

                cb.addActionListener(e -> {
                    if (cb.isSelected()) {
                        selectedHeaders.add(headerName);
                    } else {
                        removeHeaderSelection(headerName);
                    }
                    updateFromCheckboxes();
                });

                checkBoxes.put(headerName, cb);
                checkListPanel.add(cb);
            }
        }

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { filterList(searchField.getText()); }
            @Override
            public void removeUpdate(DocumentEvent e) { filterList(searchField.getText()); }
            @Override
            public void changedUpdate(DocumentEvent e) { filterList(searchField.getText()); }
        });

        JScrollPane scrollPane = new JScrollPane(checkListPanel);
        scrollPane.setPreferredSize(new Dimension(360, 220));
        scrollPane.getVerticalScrollBar().setUnitIncrement(12);
        popup.add(scrollPane, BorderLayout.CENTER);

        popup.show(textField, 0, textField.getHeight());
        searchField.requestFocusInWindow();
    }

    private void filterList(String query) {
        String q = (query != null) ? query.trim().toLowerCase() : "";
        for (Map.Entry<String, JCheckBox> entry : checkBoxes.entrySet()) {
            String name = entry.getKey().toLowerCase();
            String fullText = entry.getValue().getText().toLowerCase();
            entry.getValue().setVisible(name.contains(q) || fullText.contains(q));
        }
    }

    private void updateFromCheckboxes() {
        for (Map.Entry<String, JCheckBox> entry : checkBoxes.entrySet()) {
            entry.getValue().setSelected(isHeaderSelected(entry.getKey()));
        }
        updateTextFieldFromSelection();
        if (onSelectionChanged != null) {
            onSelectionChanged.run();
        }
    }

    private void updateTextFieldFromSelection() {
        internalUpdate = true;
        try {
            List<String> list = new ArrayList<>(selectedHeaders);
            textField.setText(String.join(", ", list));
        } finally {
            internalUpdate = false;
        }
    }

    public Set<String> getSelectedHeaderNames() {
        return new LinkedHashSet<>(selectedHeaders);
    }

    public void setSelectedHeaders(Collection<String> names) {
        selectedHeaders.clear();
        if (names != null) {
            for (String n : names) {
                if (n != null && !n.isBlank()) {
                    String matched = findMatchingHeaderKey(n.trim());
                    selectedHeaders.add(matched != null ? matched : n.trim());
                }
            }
        }
        updateTextFieldFromSelection();
        if (onSelectionChanged != null) {
            onSelectionChanged.run();
        }
    }

    public String getSelectedCookie() {
        for (String s : selectedHeaders) {
            if ("cookie".equalsIgnoreCase(s)) {
                String val = requestHeaders.get(s);
                if (val != null) return val;
                for (Map.Entry<String, String> e : requestHeaders.entrySet()) {
                    if ("cookie".equalsIgnoreCase(e.getKey())) return e.getValue();
                }
            }
        }
        return "";
    }

    public String getSelectedAgent() {
        for (String s : selectedHeaders) {
            if ("user-agent".equalsIgnoreCase(s)) {
                String val = requestHeaders.get(s);
                if (val != null) return val;
                for (Map.Entry<String, String> e : requestHeaders.entrySet()) {
                    if ("user-agent".equalsIgnoreCase(e.getKey())) return e.getValue();
                }
            }
        }
        return "";
    }

    public String getSelectedReferer() {
        for (String s : selectedHeaders) {
            if ("referer".equalsIgnoreCase(s)) {
                String val = requestHeaders.get(s);
                if (val != null) return val;
                for (Map.Entry<String, String> e : requestHeaders.entrySet()) {
                    if ("referer".equalsIgnoreCase(e.getKey())) return e.getValue();
                }
            }
        }
        return "";
    }

    /**
     * Builds the newline-delimited extra headers string for all selected headers
     * other than Cookie, User-Agent, and Referer (which use dedicated SQLMap options).
     * Includes Authorization, X-Forwarded-For, Content-Type, custom tokens, etc.
     */
    public String getSelectedHeadersString() {
        StringBuilder sb = new StringBuilder();
        for (String s : selectedHeaders) {
            if ("cookie".equalsIgnoreCase(s) || "user-agent".equalsIgnoreCase(s) || "referer".equalsIgnoreCase(s)) {
                continue;
            }
            String val = requestHeaders.get(s);
            if (val == null) {
                // Check case-insensitively
                for (Map.Entry<String, String> e : requestHeaders.entrySet()) {
                    if (e.getKey().equalsIgnoreCase(s)) {
                        val = e.getValue();
                        break;
                    }
                }
            }
            if (val != null) {
                sb.append(s).append(": ").append(val).append("\n");
            }
        }
        return sb.toString().trim();
    }

    public String getText() {
        return textField.getText().trim();
    }

    public void setText(String text) {
        textField.setText(text != null ? text : "");
        onTextChanged();
    }
}
