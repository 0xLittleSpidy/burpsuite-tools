// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

/**
 * Modal dialog displaying all active Whitelist patterns and Blacklist rules
 * utilized during JavaScript endpoint and path mining.
 *
 * @author littlespidy
 */
public class PathRegexDialog_littlespidy extends JDialog {

    public PathRegexDialog_littlespidy(Window owner) {
        super(owner, "Whitelist / Blacklist Rules", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setSize(820, 520);
        setLocationRelativeTo(owner);

        JPanel mainPanel = new JPanel(new BorderLayout(8, 8));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JTabbedPane tabbedPane = new JTabbedPane();

        // 1. Whitelist Patterns Table
        String[] whiteCols = {"#", "Engine / Category", "Description", "Pattern / Rule"};
        DefaultTableModel whiteModel = new DefaultTableModel(whiteCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        whiteModel.addRow(new Object[]{1, "Absolute URL", "Strict HTTP/HTTPS URLs with domain & optional port", "(?:\"|')https?://[^\"'/]{1,}\\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/[^\"']*)?(?:\"|')"});
        whiteModel.addRow(new Object[]{2, "Relative Path", "Relative web paths with leading / or ./ or ../", "(?:\"|')(?:/|\\.\\./|\\./)+[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,}(?:\"|')"});
        whiteModel.addRow(new Object[]{3, "REST Endpoint", "Multi-segment REST API route paths", "(?:\"|')[a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{3,}(?:[?#][^\"']*)?(?:\"|')"});
        whiteModel.addRow(new Object[]{4, "Action Route", "Endpoint path ending in action extension", "(?:\"|')[a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/.]{1,}\\.(?:action)(?:[?#][^\"']*)?(?:\"|')"});
        whiteModel.addRow(new Object[]{5, "File Extension", "API handlers and script resources (.php, .asp, .jsp, .json, .xml)", "(?:\"|')[a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?#][^\"']*)?(?:\"|')"});
        whiteModel.addRow(new Object[]{6, "HTTP Verb Call", "Client method call invocations (.get, .post, .put, .delete, .patch)", "\\.[$]?(get|post|put|delete|patch)\\(['\"`]([^'\"`\\r\\n]+)['\"`]"});
        whiteModel.addRow(new Object[]{7, "Client Route", "Framework client routing props (href, to, route, path)", "(?:href|to|route|path)\\s*[:=]\\s*[\"'](/[a-zA-Z0-9_\\-/{}.?&=#]+)[\"']"});
        whiteModel.addRow(new Object[]{8, "Webpack Chunks", "Asynchronously split and lazy-loaded Webpack chunk files", "Dynamic chunk extractors & runtime chunk mappings"});

        JTable whiteTable = new JTable(whiteModel);
        whiteTable.setRowHeight(22);
        whiteTable.getColumnModel().getColumn(0).setMaxWidth(40);
        whiteTable.getColumnModel().getColumn(1).setPreferredWidth(140);
        whiteTable.getColumnModel().getColumn(2).setPreferredWidth(220);
        whiteTable.getColumnModel().getColumn(3).setPreferredWidth(320);

        JPanel whitePanel = new JPanel(new BorderLayout());
        whitePanel.setBorder(new TitledBorder("Active Path Whitelist Patterns (LinkFinder 5-Arm and Client Routers)"));
        whitePanel.add(new JScrollPane(whiteTable), BorderLayout.CENTER);
        tabbedPane.addTab("Whitelist Patterns (8)", whitePanel);

        // 2. Blacklist Rules Table
        String[] blackCols = {"#", "Blacklist Filter", "Rule Target", "Behavior"};
        DefaultTableModel blackModel = new DefaultTableModel(blackCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        blackModel.addRow(new Object[]{1, "Module Imports/Exports", "import/export ... from '...', import('...'), require('...')", "Suppresses ES6 module imports, dynamic imports, re-exports, and CommonJS requires"});
        blackModel.addRow(new Object[]{2, "All Content-Types", "^(application|text|image|audio|video|multipart|font|model)/.*", "Suppresses all MIME Content-Type and Accept header definitions"});
        blackModel.addRow(new Object[]{3, "m/d/y and mm/dd/yy", "^\\d{1,2}/\\d{1,2}/\\d{2,4}$", "Suppresses slash-separated date strings (e.g. 1/1/24, 12/31/2026)"});
        blackModel.addRow(new Object[]{4, "yyyy/mm/dd", "^\\d{4}/\\d{1,2}/\\d{1,2}$", "Suppresses ISO slash date formats (e.g. 2026/11/04)"});
        blackModel.addRow(new Object[]{5, "//:0 (Invalid Protocol)", "^//:?\\d*$", "Suppresses invalid protocol-relative strings without http/https"});
        blackModel.addRow(new Object[]{6, "Media and Assets", "\\.(?:png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|map)", "Suppresses static fonts, images, stylesheets, and maps"});
        blackModel.addRow(new Object[]{7, "Code Artifacts", "^(?:e\\.g|i\\.e|etc|null|undefined|true|false)\\.", "Suppresses literal programming identifiers and documentation artifacts"});
        blackModel.addRow(new Object[]{8, "Numeric Sequences", "^[0-9./]+$", "Suppresses isolated numeric fractions and version strings"});

        JTable blackTable = new JTable(blackModel);
        blackTable.setRowHeight(22);
        blackTable.getColumnModel().getColumn(0).setMaxWidth(40);
        blackTable.getColumnModel().getColumn(1).setPreferredWidth(170);
        blackTable.getColumnModel().getColumn(2).setPreferredWidth(230);
        blackTable.getColumnModel().getColumn(3).setPreferredWidth(280);

        JPanel blackPanel = new JPanel(new BorderLayout());
        blackPanel.setBorder(new TitledBorder("Active Path Blacklist Filters (Strict False-Positive Suppression)"));
        blackPanel.add(new JScrollPane(blackTable), BorderLayout.CENTER);
        tabbedPane.addTab("Blacklist Rules (9)", blackPanel);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        // Close button at bottom
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());
        btnPanel.add(closeBtn);
        mainPanel.add(btnPanel, BorderLayout.SOUTH);

        setContentPane(mainPanel);
    }
}
