// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.payloadinjector.ui;

import com.littlespidy.payloadinjector.model.ParamPayloadEntry;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.UUID;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Modal dialog for creating or editing parameter-based payloads (XSS, CSTI, SQL).
 *
 * @author littlespidy
 */
public class AddEditParamPayloadDialog extends JDialog {

    private final JTextField nameField;
    private final JComboBox<String> platformCombo;
    private final JTextArea templateArea;
    private final JTextField descField;
    private final JLabel errorLabel;

    private ParamPayloadEntry result = null;

    public AddEditParamPayloadDialog(Window owner, String categoryTitle, ParamPayloadEntry existing) {
        super(owner, (existing == null ? "Add " : "Edit ") + categoryTitle + " Payload", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setResizable(true);

        boolean isEdit = existing != null;
        boolean isPathTraversal = "Path Traversal".equalsIgnoreCase(categoryTitle);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new EmptyBorder(12, 14, 6, 14));

        GridBagConstraints lc = labelConstraints();
        GridBagConstraints fc = fieldConstraints();

        int gridy = 0;

        // Name
        form.add(bold("Name *"), row(lc, gridy));
        nameField = new JTextField(isEdit ? existing.getName() : "", 35);
        form.add(nameField, row(fc, gridy++));

        // Error label
        errorLabel = new JLabel(" ");
        errorLabel.setForeground(new Color(200, 0, 0));
        errorLabel.setFont(errorLabel.getFont().deriveFont(11f));
        GridBagConstraints ec = row(fc, gridy++);
        ec.insets = new Insets(0, 4, 4, 4);
        form.add(errorLabel, ec);

        // Platform (Path Traversal only)
        if (isPathTraversal) {
            form.add(bold("Platform *"), row(lc, gridy));
            platformCombo = new JComboBox<>(new String[]{"Linux", "Windows"});
            if (isEdit && existing.getPlatform() != null && !existing.getPlatform().isBlank()) {
                platformCombo.setSelectedItem(existing.getPlatform());
            } else {
                platformCombo.setSelectedItem("Linux");
            }
            form.add(platformCombo, row(fc, gridy++));
        } else {
            platformCombo = null;
        }

        // Template
        JPanel tplLabel = new JPanel(new BorderLayout());
        tplLabel.setOpaque(false);
        tplLabel.add(bold("Payload Template *"), BorderLayout.NORTH);
        tplLabel.add(hint("Placeholders: {param}, {value}, {rand}"), BorderLayout.CENTER);
        form.add(tplLabel, row(lc, gridy));

        templateArea = new JTextArea(isEdit ? existing.getTemplate() : "", 4, 35);
        templateArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        form.add(new JScrollPane(templateArea), row(fc, gridy++));

        // Description
        form.add(bold("Description"), row(lc, gridy));
        descField = new JTextField(isEdit ? existing.getDescription() : "", 35);
        form.add(descField, row(fc, gridy++));

        // Buttons
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        JButton saveBtn = new JButton("Save");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> {
            String name = nameField.getText().trim();
            String tpl = templateArea.getText().trim();
            String desc = descField.getText().trim();

            if (name.isEmpty()) {
                errorLabel.setText("Name cannot be empty.");
                nameField.requestFocusInWindow();
                return;
            }
            if (tpl.isEmpty()) {
                errorLabel.setText("Payload template cannot be empty.");
                templateArea.requestFocusInWindow();
                return;
            }

            String id = isEdit ? existing.getId() : UUID.randomUUID().toString();
            String sourceType = isEdit ? existing.getSourceType() : "Manual";
            String sourceFile = isEdit ? existing.getSourceFile() : "N/A";
            String platform = isPathTraversal ? (String) platformCombo.getSelectedItem() : (isEdit ? existing.getPlatform() : "");
            result = new ParamPayloadEntry(id, name, tpl, desc, true, sourceType, sourceFile, platform);
            dispose();
        });

        getRootPane().setDefaultButton(saveBtn);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        buttons.add(cancelBtn);
        buttons.add(saveBtn);

        setLayout(new BorderLayout());
        add(form, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        pack();
        setMinimumSize(new Dimension(500, 280));
        setLocationRelativeTo(owner);
    }

    public ParamPayloadEntry getResult() {
        return result;
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
        return new JLabel("<html><font color='gray'><small>" + text + "</small></font></html>");
    }
}
