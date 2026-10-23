// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.ui;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.List;

/**
 * Standalone Java Swing GUI Preview Runner for Retire.js integration in JavaScript Inspector.
 * Demonstrates the exact look and feel of the "JS and Source Map" tab, top table with the new
 * Retire.js Vulnerabilities column, and the bottom Retire.js inspection sub-tab.
 *
 * @author littlespidy
 */
public class RetireJsSwingPreviewRunner_littlespidy {

    private static final Color COLOR_BG = new Color(0x1e, 0x1e, 0x1e);
    private static final Color COLOR_PANEL = new Color(0x25, 0x25, 0x26);
    private static final Color COLOR_DARK = new Color(0x14, 0x14, 0x14);
    private static final Color COLOR_BORDER = new Color(0x3c, 0x3c, 0x3c);
    private static final Color COLOR_TEXT = new Color(0xcc, 0xcc, 0xcc);
    private static final Color COLOR_TEXT_BRIGHT = Color.WHITE;
    private static final Color COLOR_ACCENT = new Color(0xe5, 0x6b, 0x1f); // Burp Orange
    private static final Color COLOR_HIGH = new Color(0xf1, 0x4c, 0x4c);
    private static final Color COLOR_MED = new Color(0xcc, 0xa7, 0x00);
    private static final Color COLOR_CLEAN = new Color(0x1f, 0x8a, 0x4c);

    public static void main(String[] args) {
        boolean headless = (args.length > 0 && "--headless".equalsIgnoreCase(args[0]));

        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
            } catch (Exception ignored) {}

            JFrame frame = new JFrame("Burp Suite Professional - JavaScript Inspector (littlespidy) [Swing Preview]");
            frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            frame.setSize(1280, 820);
            frame.setLocationRelativeTo(null);

            JPanel rootPanel = createMainPreviewPanel();
            frame.setContentPane(rootPanel);

            // Export high-resolution PNG screenshot
            frame.pack();
            frame.setSize(1280, 820);
            frame.validate();

            captureComponentImage(rootPanel, new File("retirejs_swing_preview_littlespidy.png"));

            if (headless) {
                System.out.println("Screenshot saved to retirejs_swing_preview_littlespidy.png");
                System.exit(0);
            }
        });
    }

    public static JPanel createMainPreviewPanel() {
        JPanel container = new JPanel(new BorderLayout());
        container.setBackground(COLOR_BG);

        // -- Fake Burp Suite Header & Suite Tabs --
        JPanel topSuitePanel = new JPanel(new BorderLayout());
        topSuitePanel.setBackground(COLOR_DARK);

        JPanel headerBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        headerBar.setBackground(COLOR_DARK);
        JLabel burpBadge = new JLabel(" BURP ");
        burpBadge.setOpaque(true);
        burpBadge.setBackground(COLOR_ACCENT);
        burpBadge.setForeground(Color.WHITE);
        burpBadge.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        headerBar.add(burpBadge);

        JLabel titleLbl = new JLabel("Burp Suite Professional - JavaScript Inspector (littlespidy)");
        titleLbl.setForeground(COLOR_TEXT_BRIGHT);
        titleLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        headerBar.add(titleLbl);
        topSuitePanel.add(headerBar, BorderLayout.NORTH);

        // Suite Tabs Bar
        JTabbedPane fakeSuiteTabs = new JTabbedPane();
        fakeSuiteTabs.setBackground(COLOR_DARK);
        fakeSuiteTabs.setForeground(COLOR_TEXT);
        fakeSuiteTabs.addTab("Dashboard", new JPanel());
        fakeSuiteTabs.addTab("Target", new JPanel());
        fakeSuiteTabs.addTab("Proxy", new JPanel());
        fakeSuiteTabs.addTab("Repeater", new JPanel());

        // Main Extension Tab
        JPanel extTabContent = createExtensionTabContent();
        fakeSuiteTabs.addTab("JavaScript Inspector", extTabContent);
        fakeSuiteTabs.setSelectedComponent(extTabContent);
        topSuitePanel.add(fakeSuiteTabs, BorderLayout.CENTER);

        container.add(topSuitePanel, BorderLayout.CENTER);
        return container;
    }

    private static JPanel createExtensionTabContent() {
        JPanel extPanel = new JPanel(new BorderLayout());
        extPanel.setBackground(COLOR_BG);

        // Extension Root Tabs
        JTabbedPane extTabs = new JTabbedPane();
        extTabs.setBackground(COLOR_BG);
        extTabs.setForeground(COLOR_TEXT);

        JPanel jsAndMapWorkspace = createJsAndMapWorkspace();
        extTabs.addTab("JS and Source Map", jsAndMapWorkspace);
        extTabs.addTab("Recon and Secret Mining", new JPanel());
        extTabs.addTab("GraphQL", new JPanel());
        extTabs.addTab("AI Security Analyst", new JPanel());

        extPanel.add(extTabs, BorderLayout.CENTER);
        return extPanel;
    }

    private static JPanel createJsAndMapWorkspace() {
        JPanel workspace = new JPanel(new BorderLayout(5, 5));
        workspace.setBackground(COLOR_BG);
        workspace.setBorder(new EmptyBorder(6, 6, 6, 6));

        // -- Top Toolbars --
        JPanel topBars = new JPanel(new GridLayout(2, 1, 4, 4));
        topBars.setBackground(COLOR_BG);

        // Action Toolbar
        JPanel bar1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        bar1.setBackground(COLOR_PANEL);
        bar1.setBorder(new LineBorder(COLOR_BORDER));

        JButton loadBtn = new JButton("Load Proxy History");
        loadBtn.setBackground(COLOR_ACCENT);
        loadBtn.setForeground(Color.WHITE);
        bar1.add(loadBtn);

        JCheckBox inScopeCheck = new JCheckBox("In-Scope Only", true);
        inScopeCheck.setBackground(COLOR_PANEL);
        inScopeCheck.setForeground(COLOR_TEXT);
        bar1.add(inScopeCheck);

        JComboBox<String> domainCombo = new JComboBox<>(new String[]{"All Domains (2)", "app.example-portal.com", "cdn.external-assets.com"});
        domainCombo.setBackground(COLOR_DARK);
        domainCombo.setForeground(COLOR_TEXT);
        bar1.add(domainCombo);

        bar1.add(new JSeparator(SwingConstants.VERTICAL));
        bar1.add(createDarkButton("Select All"));
        bar1.add(createDarkButton("Deselect All"));
        bar1.add(createDarkButton("Copy JS URLs"));
        bar1.add(new JSeparator(SwingConstants.VERTICAL));
        bar1.add(createDarkButton("Download JS File(s)..."));
        bar1.add(createDarkButton("Scan Selected (.map)"));
        bar1.add(createDarkButton("Scan All (.map)"));
        bar1.add(createDarkButton("Unpack Selected .map"));
        bar1.add(new JSeparator(SwingConstants.VERTICAL));

        // Retire.js buttons
        JButton scanSelectedRetireBtn = createDarkButton("Scan Selected (Retire JS)");
        scanSelectedRetireBtn.setForeground(new Color(0x79, 0xc0, 0xff));
        bar1.add(scanSelectedRetireBtn);

        JButton scanAllRetireBtn = createDarkButton("Scan All (Retire JS)");
        scanAllRetireBtn.setForeground(new Color(0x79, 0xc0, 0xff));
        bar1.add(scanAllRetireBtn);

        JComboBox<String> dbCombo = new JComboBox<>(new String[]{
            "Retire.js DB: v3.0.4 (3,420 signatures)",
            "Update Retire.js DB Online...",
            "Reload Bundled DB"
        });
        dbCombo.setBackground(COLOR_DARK);
        dbCombo.setForeground(COLOR_TEXT);
        bar1.add(dbCombo);

        topBars.add(bar1);

        // Filter Toolbar
        JPanel bar2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        bar2.setBackground(COLOR_PANEL);
        bar2.setBorder(new LineBorder(COLOR_BORDER));

        JCheckBox expMapCheck = new JCheckBox("Exposed .map Only", false);
        expMapCheck.setBackground(COLOR_PANEL);
        expMapCheck.setForeground(COLOR_TEXT);
        bar2.add(expMapCheck);

        JCheckBox vulnOnlyCheck = new JCheckBox("Vulnerable Only (Retire.js)", false);
        vulnOnlyCheck.setBackground(COLOR_PANEL);
        vulnOnlyCheck.setForeground(COLOR_HIGH);
        vulnOnlyCheck.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        bar2.add(vulnOnlyCheck);

        bar2.add(new JSeparator(SwingConstants.VERTICAL));
        JLabel sevLbl = new JLabel("Severity Filter:");
        sevLbl.setForeground(COLOR_TEXT);
        bar2.add(sevLbl);
        JComboBox<String> sevCombo = new JComboBox<>(new String[]{"All Severities", "High Severity Only", "Medium and Above", "Clean Only"});
        sevCombo.setBackground(COLOR_DARK);
        sevCombo.setForeground(COLOR_TEXT);
        bar2.add(sevCombo);

        bar2.add(new JSeparator(SwingConstants.VERTICAL));
        JLabel searchLbl = new JLabel("Search:");
        searchLbl.setForeground(COLOR_TEXT);
        bar2.add(searchLbl);
        JTextField searchField = new JTextField(15);
        searchField.setBackground(COLOR_DARK);
        searchField.setForeground(COLOR_TEXT_BRIGHT);
        searchField.setCaretColor(COLOR_TEXT_BRIGHT);
        bar2.add(searchField);

        JLabel statsLbl = new JLabel("Total: 6 | 1st Party: 4 | .map Exposed: 2 | Vulnerable (Retire.js): 4");
        statsLbl.setForeground(new Color(0xff, 0xa5, 0x00));
        statsLbl.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        bar2.add(statsLbl);

        topBars.add(bar2);
        workspace.add(topBars, BorderLayout.NORTH);

        // -- Center Split Pane: Top Scripts Table vs Bottom Inspection Tabs --
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.40);
        mainSplit.setBorder(null);

        // Top Scripts Table Panel
        JPanel scriptsPanel = new JPanel(new BorderLayout());
        scriptsPanel.setBorder(new TitledBorder(new LineBorder(COLOR_BORDER), "Discovered JavaScript Scripts (Deduplicated)",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 12), COLOR_TEXT_BRIGHT));
        scriptsPanel.setBackground(COLOR_PANEL);

        String[] cols = {
            "#", "Framework", "Status", "Host", "JS Path", "Retire.js Vulnerabilities", "Passive .map", "Probe", "Unpacked", "Size"
        };
        Object[][] data = {
            {1, "jQuery", 200, "app.example-portal.com", "/static/js/vendor.jquery-1.8.2.min.js", "[HIGH] jQuery 1.8.2 (4 CVEs)", "Header", "Found", "48 files", "92.4 KB"},
            {2, "-", 200, "app.example-portal.com", "/assets/libs/lodash.4.17.4.js", "[HIGH] Lodash 4.17.4 (2 CVEs)", "None", "-", "-", "71.1 KB"},
            {3, "Angular", 200, "app.example-portal.com", "/legacy/angular.1.5.8.min.js", "[MED] AngularJS 1.5.8 (3 CVEs)", "Header", "Found", "112 files", "145.2 KB"},
            {4, "-", 200, "cdn.external-assets.com", "/ui/bootstrap-3.3.7.min.js", "[MED] Bootstrap 3.3.7 (2 CVEs)", "None", "-", "-", "37.0 KB"},
            {5, "React", 200, "app.example-portal.com", "/static/chunks/react-dom.18.2.0.min.js", "Clean (0 Known CVEs)", "Body", "Found", "254 files", "131.5 KB"},
            {6, "Next.js", 200, "app.example-portal.com", "/_next/static/chunks/main-app-9c48b2.js", "Clean (0 Known CVEs)", "Body", "Found", "310 files", "289.4 KB"}
        };

        DefaultTableModel model = new DefaultTableModel(data, cols);
        JTable table = new JTable(model);
        styleDarkTable(table);

        // Custom Renderer for Retire.js column
        table.getColumnModel().getColumn(5).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object val, boolean isSel, boolean hasFoc, int row, int col) {
                Component c = super.getTableCellRendererComponent(tbl, val, isSel, hasFoc, row, col);
                String str = String.valueOf(val);
                if (isSel) {
                    c.setBackground(new Color(0x09, 0x47, 0x71));
                    c.setForeground(Color.WHITE);
                } else {
                    c.setBackground(COLOR_PANEL);
                    if (str.startsWith("[HIGH]")) {
                        c.setForeground(COLOR_HIGH);
                    } else if (str.startsWith("[MED]")) {
                        c.setForeground(COLOR_MED);
                    } else if (str.startsWith("Clean")) {
                        c.setForeground(COLOR_CLEAN);
                    } else {
                        c.setForeground(COLOR_TEXT);
                    }
                }
                setFont(getFont().deriveFont(Font.BOLD));
                return c;
            }
        });

        table.setRowSelectionInterval(0, 0); // select row 1 by default
        scriptsPanel.add(new JScrollPane(table), BorderLayout.CENTER);
        mainSplit.setTopComponent(scriptsPanel);

        // Bottom Inspection Tabs: Javascript, Sourcemap, Reconstructed Source Tree, Retire.js
        JTabbedPane bottomTabs = new JTabbedPane();
        bottomTabs.setBackground(COLOR_DARK);
        bottomTabs.setForeground(COLOR_TEXT);

        bottomTabs.addTab("Javascript", new JPanel());
        bottomTabs.addTab("Sourcemap", new JPanel());
        bottomTabs.addTab("Reconstructed Source Tree", new JPanel());

        // Sub-Tab 4: Retire.js Vulnerabilities Panel
        JPanel retirePanel = createRetireJsTabPanel();
        bottomTabs.addTab("Retire.js Vulnerabilities (4)", retirePanel);
        bottomTabs.setSelectedComponent(retirePanel);

        mainSplit.setBottomComponent(bottomTabs);
        workspace.add(mainSplit, BorderLayout.CENTER);

        return workspace;
    }

    private static JPanel createRetireJsTabPanel() {
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBackground(COLOR_BG);
        panel.setBorder(new EmptyBorder(6, 6, 6, 6));

        // -- Top Summary Header Card --
        JPanel headerCard = new JPanel(new BorderLayout(8, 8));
        headerCard.setBackground(COLOR_DARK);
        headerCard.setBorder(new CompoundBorder(
            new LineBorder(COLOR_HIGH, 2),
            new EmptyBorder(8, 12, 8, 12)
        ));

        JPanel titleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        titleRow.setBackground(COLOR_DARK);

        JLabel libTitle = new JLabel("jQuery 1.8.2");
        libTitle.setForeground(COLOR_TEXT_BRIGHT);
        libTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 15));
        titleRow.add(libTitle);

        JLabel riskBadge = new JLabel(" HIGH RISK VULNERABILITY ");
        riskBadge.setOpaque(true);
        riskBadge.setBackground(COLOR_HIGH);
        riskBadge.setForeground(Color.WHITE);
        riskBadge.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        titleRow.add(riskBadge);

        headerCard.add(titleRow, BorderLayout.NORTH);

        JPanel metaGrid = new JPanel(new GridLayout(1, 3, 15, 0));
        metaGrid.setBackground(COLOR_DARK);

        metaGrid.add(createMetaLabel("DETECTION METHOD", "Content Pattern Match: /*! jQuery v1.8.2"));
        metaGrid.add(createMetaLabel("TARGET ASSET", "/static/js/vendor.jquery-1.8.2.min.js"));
        metaGrid.add(createMetaLabel("VULNERABILITIES BREAKDOWN", "4 Known CVEs (2 High, 2 Medium)"));

        headerCard.add(metaGrid, BorderLayout.CENTER);
        panel.add(headerCard, BorderLayout.NORTH);

        // -- Split View: Left CVE Table vs Right Detail Inspector --
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split.setResizeWeight(0.52);
        split.setBorder(null);

        // Left Table
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBackground(COLOR_PANEL);
        leftPanel.setBorder(new TitledBorder(new LineBorder(COLOR_BORDER), "Vulnerabilities and Security Advisories",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 11), COLOR_TEXT_BRIGHT));

        String[] vCols = {"#", "Severity", "CVE / Identifier", "Affected Versions", "Summary"};
        Object[][] vData = {
            {1, "HIGH", "CVE-2015-9251", "< 3.0.0", "3rd party CORS request execution leads to arbitrary code"},
            {2, "HIGH", "CVE-2020-11022", ">= 1.2.0, < 3.5.0", "Cross-site scripting (XSS) in jQuery.htmlPrefilter regex"},
            {3, "MEDIUM", "CVE-2019-11358", "< 3.4.0", "Prototype pollution vulnerability via jQuery.extend"},
            {4, "MEDIUM", "CVE-2020-11023", ">= 1.0.3, < 3.5.0", "XSS in jQuery.htmlPrefilter with untrusted HTML"}
        };
        DefaultTableModel vModel = new DefaultTableModel(vData, vCols);
        JTable vTable = new JTable(vModel);
        styleDarkTable(vTable);

        // Severity column coloring
        vTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object val, boolean isSel, boolean hasFoc, int row, int col) {
                Component c = super.getTableCellRendererComponent(tbl, val, isSel, hasFoc, row, col);
                if (!isSel) {
                    if ("HIGH".equals(val)) {
                        c.setForeground(COLOR_HIGH);
                    } else if ("MEDIUM".equals(val)) {
                        c.setForeground(COLOR_MED);
                    } else {
                        c.setForeground(COLOR_CLEAN);
                    }
                    setFont(getFont().deriveFont(Font.BOLD));
                }
                return c;
            }
        });

        vTable.setRowSelectionInterval(0, 0);
        leftPanel.add(new JScrollPane(vTable), BorderLayout.CENTER);
        split.setLeftComponent(leftPanel);

        // Right Detail Inspector
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBackground(COLOR_PANEL);
        rightPanel.setBorder(new TitledBorder(new LineBorder(COLOR_BORDER), "Vulnerability Details and Remediation Guidance",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(Font.SANS_SERIF, Font.BOLD, 11), COLOR_TEXT_BRIGHT));

        JPanel detailContent = new JPanel();
        detailContent.setLayout(new BoxLayout(detailContent, BoxLayout.Y_AXIS));
        detailContent.setBackground(COLOR_PANEL);
        detailContent.setBorder(new EmptyBorder(8, 10, 8, 10));

        JLabel vulnTitle = new JLabel("CVE-2015-9251: 3rd party CORS request execution");
        vulnTitle.setForeground(COLOR_HIGH);
        vulnTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        detailContent.add(vulnTitle);
        detailContent.add(Box.createVerticalStrut(8));

        detailContent.add(createSectionHeader("DESCRIPTION AND SECURITY IMPACT"));
        JTextArea descArea = createReadOnlyTextArea(
            "jQuery versions prior to 3.0.0 are vulnerable to Cross-Site Scripting (XSS). When using $.ajax() " +
            "with dataType 'script' or when cross-domain requests without an explicit dataType are executed, " +
            "responses from third-party or untrusted servers may execute arbitrary JavaScript in the context of the application."
        );
        detailContent.add(descArea);
        detailContent.add(Box.createVerticalStrut(8));

        detailContent.add(createSectionHeader("REMEDIATION GUIDANCE"));
        JTextArea remArea = createReadOnlyTextArea(
            "Upgrade jQuery to version 3.5.0 or later. If upgrading is blocked by legacy plugins, configure " +
            "$.ajaxSetup({ dataType: 'json' }) or enforce strict CORS policies to avoid auto-evaluating untrusted responses."
        );
        remArea.setForeground(new Color(0x79, 0xc0, 0xff));
        detailContent.add(remArea);
        detailContent.add(Box.createVerticalStrut(8));

        detailContent.add(createSectionHeader("MATCHED EVIDENCE IN JAVASCRIPT ASSET"));
        JTextArea codeArea = createReadOnlyTextArea(
            "/*! jQuery v1.8.2 jquery.com | jquery.org/license */\n" +
            "(function( window, undefined ) {\n" +
            "  var rootjQuery,\n" +
            "  core_strundefined = typeof undefined,\n" +
            "  location = window.location,\n" +
            "  document = window.document,"
        );
        codeArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        codeArea.setBackground(COLOR_DARK);
        codeArea.setForeground(new Color(0x79, 0xc0, 0xff));
        codeArea.setBorder(new CompoundBorder(new LineBorder(COLOR_BORDER), new EmptyBorder(4, 6, 4, 6)));
        detailContent.add(codeArea);
        detailContent.add(Box.createVerticalStrut(8));

        detailContent.add(createSectionHeader("ADVISORY REFERENCES"));
        JTextArea linksArea = createReadOnlyTextArea(
            "- https://nvd.nist.gov/vuln/detail/CVE-2015-9251\n" +
            "- https://github.com/jquery/jquery/issues/2432\n" +
            "- https://blog.jquery.com/2016/06/09/jquery-3-0-final-released/"
        );
        linksArea.setForeground(new Color(0x58, 0xa6, 0xff));
        detailContent.add(linksArea);

        rightPanel.add(new JScrollPane(detailContent), BorderLayout.CENTER);
        split.setRightComponent(rightPanel);

        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private static JPanel createMetaLabel(String title, String value) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(COLOR_DARK);
        JLabel t = new JLabel(title);
        t.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 9));
        t.setForeground(new Color(0x8e, 0x8e, 0x8e));
        JLabel v = new JLabel(value);
        v.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        v.setForeground(COLOR_TEXT_BRIGHT);
        p.add(t, BorderLayout.NORTH);
        p.add(v, BorderLayout.CENTER);
        return p;
    }

    private static JLabel createSectionHeader(String title) {
        JLabel l = new JLabel(title);
        l.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
        l.setForeground(COLOR_ACCENT);
        l.setBorder(new EmptyBorder(4, 0, 2, 0));
        return l;
    }

    private static JTextArea createReadOnlyTextArea(String text) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBackground(COLOR_PANEL);
        area.setForeground(COLOR_TEXT);
        area.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        return area;
    }

    private static JButton createDarkButton(String text) {
        JButton b = new JButton(text);
        b.setBackground(new Color(0x33, 0x33, 0x33));
        b.setForeground(COLOR_TEXT_BRIGHT);
        b.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        b.setBorder(new CompoundBorder(new LineBorder(COLOR_BORDER), new EmptyBorder(3, 8, 3, 8)));
        return b;
    }

    private static void styleDarkTable(JTable table) {
        table.setBackground(COLOR_PANEL);
        table.setForeground(COLOR_TEXT);
        table.setGridColor(COLOR_BORDER);
        table.setRowHeight(24);
        table.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        table.setSelectionBackground(new Color(0x09, 0x47, 0x71));
        table.setSelectionForeground(Color.WHITE);
        table.getTableHeader().setBackground(COLOR_DARK);
        table.getTableHeader().setForeground(COLOR_TEXT_BRIGHT);
        table.getTableHeader().setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        table.getTableHeader().setBorder(new LineBorder(COLOR_BORDER));
    }

    private static void captureComponentImage(Component comp, File file) {
        try {
            BufferedImage image = new BufferedImage(comp.getWidth(), comp.getHeight(), BufferedImage.TYPE_INT_RGB);
            Graphics2D g2 = image.createGraphics();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            comp.paint(g2);
            g2.dispose();
            ImageIO.write(image, "PNG", file);
            System.out.println("Screenshot successfully written to: " + file.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Failed to capture screenshot: " + e.getMessage());
        }
    }
}
