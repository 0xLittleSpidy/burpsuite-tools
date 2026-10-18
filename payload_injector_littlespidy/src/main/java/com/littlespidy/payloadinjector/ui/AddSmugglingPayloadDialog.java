// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import com.littlespidy.payloadinjector.model.SmugglingPayloadEntry;
import com.littlespidy.payloadinjector.model.SmugglingPayloadStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Modal dialog for creating or editing an HTTP request smuggling payload.
 *
 * @author littlespidy
 */
public class AddSmugglingPayloadDialog extends JDialog {

    private final JTextField nameField;
    private final JTextField descField;
    private final JTextArea headersArea;
    private final JTextArea bodyArea;
    private final JLabel nameErrorLabel;

    private final SmugglingPayloadStore store;
    private final SmugglingPayloadEntry existing;
    private SmugglingPayloadEntry result = null;

    public AddSmugglingPayloadDialog(Window owner, SmugglingPayloadStore store, SmugglingPayloadEntry existing) {
        super(owner, (existing == null ? "Add " : "Edit ") + "HTTP Request Smuggling Payload", ModalityType.APPLICATION_MODAL);
        this.store = store;
        this.existing = existing;

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setResizable(true);

        boolean isEdit = existing != null;
        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new EmptyBorder(12, 14, 6, 14));

        GridBagConstraints lc = labelConstraints();
        GridBagConstraints fc = fieldConstraints();

        // Row 0 — Name
        form.add(bold("Name *"), row(lc, 0));
        nameField = new JTextField(isEdit ? existing.getName() : "", 40);
        form.add(nameField, row(fc, 0));

        // Row 1 — Error Label
        nameErrorLabel = new JLabel(" ");
        nameErrorLabel.setForeground(new Color(200, 0, 0));
        nameErrorLabel.setFont(nameErrorLabel.getFont().deriveFont(11f));
        GridBagConstraints ec = row(fc, 1);
        ec.insets = new Insets(0, 4, 4, 4);
        form.add(nameErrorLabel, ec);

        // Row 2 — Description
        form.add(bold("Description"), row(lc, 2));
        descField = new JTextField(isEdit ? existing.getDescription() : "", 40);
        form.add(descField, row(fc, 2));

        // Row 3 — Headers
        JPanel headersLabel = new JPanel(new BorderLayout());
        headersLabel.setOpaque(false);
        headersLabel.add(bold("Headers"), BorderLayout.NORTH);
        headersLabel.add(hint("one per line:\nHeader: Value"), BorderLayout.CENTER);
        form.add(headersLabel, row(lc, 3));

        StringBuilder initialHeaders = new StringBuilder();
        if (isEdit) {
            existing.getHeaders().forEach((k, v) -> initialHeaders.append(k).append(": ").append(v).append("\n"));
        }
        headersArea = new JTextArea(initialHeaders.toString().stripTrailing(), 5, 40);
        headersArea.setFont(mono);
        headersArea.setTabSize(4);
        form.add(scrollWrap(headersArea), row(fc, 3));

        // Row 4 — Body
        JPanel bodyLabel = new JPanel(new BorderLayout());
        bodyLabel.setOpaque(false);
        bodyLabel.add(bold("Body"), BorderLayout.NORTH);
        bodyLabel.add(hint("use \\r\\n for CR+LF"), BorderLayout.CENTER);
        form.add(bodyLabel, row(lc, 4));

        bodyArea = new JTextArea(isEdit ? existing.getBody() : "", 5, 40);
        bodyArea.setFont(mono);
        bodyArea.setTabSize(4);
        form.add(scrollWrap(bodyArea), row(fc, 4));

        // Buttons
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        JButton saveBtn = new JButton("Save");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> attemptSave());

        getRootPane().setDefaultButton(saveBtn);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        buttons.add(cancelBtn);
        buttons.add(saveBtn);

        setLayout(new BorderLayout());
        add(form, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        pack();
        setMinimumSize(new Dimension(540, 380));
        setLocationRelativeTo(owner);
    }

    public SmugglingPayloadEntry getResult() {
        return result;
    }

    private void attemptSave() {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            nameErrorLabel.setText("Name is required.");
            nameField.requestFocusInWindow();
            return;
        }
        nameErrorLabel.setText(" ");

        // Check for duplicate name if new or if name changed
        if (existing == null || !existing.getName().equalsIgnoreCase(name)) {
            List<String> existingNames = store.getEntries().stream()
                    .map(e -> e.getName().toLowerCase())
                    .toList();
            if (existingNames.contains(name.toLowerCase())) {
                int choice = JOptionPane.showConfirmDialog(this,
                        "A payload named \"" + name + "\" already exists.\nSave anyway?",
                        "Duplicate Name",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.WARNING_MESSAGE);
                if (choice != JOptionPane.YES_OPTION) return;
            }
        }

        String description = descField.getText().trim();
        Map<String, String> headers = parseHeaders(headersArea.getText());
        String body = bodyArea.getText();

        String sourceType = (existing != null) ? existing.getSourceType() : "Manual";
        String sourceFile = (existing != null) ? existing.getSourceFile() : "N/A";

        result = new SmugglingPayloadEntry(name, description, headers, body, sourceType, sourceFile);
        dispose();
    }

    private static Map<String, String> parseHeaders(String text) {
        Map<String, String> map = new LinkedHashMap<>();
        if (text == null || text.isBlank()) return map;
        for (String line : text.lines().toList()) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String key = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                if (!key.isEmpty()) map.put(key, value);
            }
        }
        return map;
    }

    private static GridBagConstraints row(GridBagConstraints base, int row) {
        GridBagConstraints c = (GridBagConstraints) base.clone();
        c.gridy = row;
        return c;
    }

    private static GridBagConstraints labelConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.insets = new Insets(6, 4, 4, 10);
        return c;
    }

    private static GridBagConstraints fieldConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 1;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.insets = new Insets(6, 4, 4, 4);
        return c;
    }

    private static JLabel bold(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD));
        return l;
    }

    private static JLabel hint(String text) {
        return new JLabel("<html><font color='gray'><small>"
                + text.replace("\n", "<br>") + "</small></font></html>");
    }

    private static JScrollPane scrollWrap(JTextArea area) {
        JScrollPane sp = new JScrollPane(area);
        sp.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        return sp;
    }
}
