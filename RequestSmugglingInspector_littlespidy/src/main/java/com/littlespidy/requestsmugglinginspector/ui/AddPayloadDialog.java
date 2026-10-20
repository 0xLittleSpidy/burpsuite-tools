// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.requestsmugglinginspector.ui;

import com.littlespidy.requestsmugglinginspector.model.PayloadEntry;
import com.littlespidy.requestsmugglinginspector.model.PayloadStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Modal dialog that allows the user to create a new HTTP request-smuggling
 * payload from within the Burp Suite UI.
 *
 * <p>Fields:
 * <ul>
 *   <li><b>Name</b> (required) - display label used in the table and context menu.</li>
 *   <li><b>Description</b> (optional) - tooltip / notes shown in the detail pane.</li>
 *   <li><b>Headers</b> (text area) - one {@code Header-Name: value} per line.</li>
 *   <li><b>Body</b> (text area) - use {@code \r\n} for CR+LF (decoded on injection).</li>
 * </ul>
 *
 * <p>When the user clicks <em>Save</em>, the entry is passed to
 * {@link PayloadStore#addEntry(PayloadEntry)}, which appends it to the
 * in-memory list <em>and</em> immediately persists {@code smuggling-payloads.json}.
 *
 * <p>Check {@link #isSaved()} after {@code setVisible(true)} returns to know
 * whether the user completed the save or cancelled.
 *
 * @author littlespidy
 */
public class AddPayloadDialog extends JDialog {

    private boolean saved = false;

    // Input fields
    private final JTextField  nameField;
    private final JTextField  descField;
    private final JTextArea   headersArea;
    private final JTextArea   bodyArea;
    private final JLabel      nameErrorLabel;

    private final PayloadStore store;

    /**
     * @param owner the parent {@link Window} - used to centre and block the dialog
     * @param store the payload store to which the new entry will be added
     */
    public AddPayloadDialog(Window owner, PayloadStore store) {
        super(owner, "Add New Payload", ModalityType.APPLICATION_MODAL);
        this.store = store;

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setResizable(true);

        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);

        // -- Form panel --------------------------------------------------------
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new EmptyBorder(12, 14, 6, 14));

        GridBagConstraints lc = labelConstraints();
        GridBagConstraints fc = fieldConstraints();

        // Row 0 - Name
        form.add(bold("Name *"), row(lc, 0));
        nameField = new JTextField(40);
        form.add(nameField, row(fc, 0));

        // Row 1 - Name error label (hidden until validation fires)
        nameErrorLabel = new JLabel(" ");
        nameErrorLabel.setForeground(new Color(200, 0, 0));
        nameErrorLabel.setFont(nameErrorLabel.getFont().deriveFont(11f));
        GridBagConstraints ec = row(fc, 1);
        ec.insets = new Insets(0, 4, 4, 4);
        form.add(nameErrorLabel, ec);

        // Row 2 - Description
        form.add(bold("Description"), row(lc, 2));
        descField = new JTextField(40);
        form.add(descField, row(fc, 2));

        // Row 3 - Headers label + hint
        JPanel headersLabel = new JPanel(new BorderLayout());
        headersLabel.setOpaque(false);
        headersLabel.add(bold("Headers"), BorderLayout.NORTH);
        headersLabel.add(hint("one per line:\nHeader: Value"), BorderLayout.CENTER);
        form.add(headersLabel, row(lc, 3));

        headersArea = new JTextArea(5, 40);
        headersArea.setFont(mono);
        headersArea.setTabSize(4);
        form.add(scrollWrap(headersArea), row(fc, 3));

        // Row 4 - Body label + hint
        JPanel bodyLabel = new JPanel(new BorderLayout());
        bodyLabel.setOpaque(false);
        bodyLabel.add(bold("Body"), BorderLayout.NORTH);
        bodyLabel.add(hint("use \\r\\n for CR+LF"), BorderLayout.CENTER);
        form.add(bodyLabel, row(lc, 4));

        bodyArea = new JTextArea(5, 40);
        bodyArea.setFont(mono);
        bodyArea.setTabSize(4);
        form.add(scrollWrap(bodyArea), row(fc, 4));

        // -- Button row --------------------------------------------------------
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        JButton saveBtn = new JButton("Save");
        saveBtn.setFont(saveBtn.getFont().deriveFont(Font.BOLD));
        saveBtn.addActionListener(e -> attemptSave());

        // Make Save the default button (activated by Enter key)
        getRootPane().setDefaultButton(saveBtn);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        buttons.add(cancelBtn);
        buttons.add(saveBtn);

        // -- Layout ------------------------------------------------------------
        setLayout(new BorderLayout());
        add(form,    BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        pack();
        setMinimumSize(new Dimension(540, 380));
        setLocationRelativeTo(owner);
    }

    // -- Public API ------------------------------------------------------------

    /**
     * Returns {@code true} if the user completed the dialog by clicking
     * <em>Save</em>, {@code false} if they cancelled or closed the window.
     */
    public boolean isSaved() { return saved; }

    // -- Private helpers -------------------------------------------------------

    private void attemptSave() {
        String name = nameField.getText().trim();

        // Validate: name is required
        if (name.isEmpty()) {
            nameErrorLabel.setText("Name is required.");
            nameField.requestFocusInWindow();
            return;
        }
        nameErrorLabel.setText(" ");

        // Warn about duplicate name (non-blocking)
        List<String> existingNames = store.getEntries().stream()
                .map(e -> e.getName().toLowerCase())
                .toList();
        if (existingNames.contains(name.toLowerCase())) {
            int choice = JOptionPane.showConfirmDialog(this,
                    "A payload named \"" + name + "\" already exists.\n"
                    + "Save anyway?",
                    "Duplicate Name",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) return;
        }

        String description = descField.getText().trim();
        Map<String, String> headers = parseHeaders(headersArea.getText());
        String body = bodyArea.getText();   // kept as-is; \r\n decoded on injection

        PayloadEntry entry = new PayloadEntry(name, description, headers, body);
        store.addEntry(entry);   // adds to list + saves JSON

        saved = true;
        dispose();
    }

    /**
     * Parses the headers text area into an ordered map.
     * Each line must be {@code "Header-Name: value"} - lines that do not
     * contain a colon are silently skipped.
     */
    private static Map<String, String> parseHeaders(String text) {
        Map<String, String> map = new LinkedHashMap<>();
        if (text == null || text.isBlank()) return map;
        for (String line : text.lines().toList()) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String key   = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                if (!key.isEmpty()) map.put(key, value);
            }
        }
        return map;
    }

    // -- Layout utility methods ------------------------------------------------

    private static GridBagConstraints row(GridBagConstraints base, int row) {
        GridBagConstraints c = (GridBagConstraints) base.clone();
        c.gridy = row;
        return c;
    }

    private static GridBagConstraints labelConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx   = 0;
        c.anchor  = GridBagConstraints.NORTHWEST;
        c.fill    = GridBagConstraints.NONE;
        c.weightx = 0;
        c.insets  = new Insets(6, 4, 4, 10);
        return c;
    }

    private static GridBagConstraints fieldConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx   = 1;
        c.anchor  = GridBagConstraints.NORTHWEST;
        c.fill    = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.insets  = new Insets(6, 4, 4, 4);
        return c;
    }

    private static JLabel bold(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD));
        return l;
    }

    private static JLabel hint(String text) {
        JLabel l = new JLabel("<html><font color='gray'><small>"
                + text.replace("\n", "<br>") + "</small></font></html>");
        return l;
    }

    private static JScrollPane scrollWrap(JTextArea area) {
        JScrollPane sp = new JScrollPane(area);
        sp.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        return sp;
    }
}
