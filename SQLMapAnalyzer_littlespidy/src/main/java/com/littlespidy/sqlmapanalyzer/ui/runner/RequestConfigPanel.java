// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.ui.runner;

import com.littlespidy.sqlmapanalyzer.api.model.SqlmapTaskOptions;
import com.littlespidy.sqlmapanalyzer.util.SwingUtils;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * Left-hand configuration panel for setting SQLMap scan options.
 * Plain ASCII text only.
 */
public class RequestConfigPanel extends JPanel {

    private final JTextField txtParam;
    private final JComboBox<Integer> comboLevel;
    private final JComboBox<Integer> comboRisk;
    private final JTextField txtTechnique;
    private final JComboBox<String> comboDbms;
    private final JTextField txtOs;
    private final MultiSelectTamperDropdown_littlespidy tamperDropdown;

    private final MultiSelectHeaderDropdown_littlespidy headerDropdown;
    private final JLabel lblHeaderSummary;

    private final JTextField txtDb;
    private final JTextField txtTbl;
    private final JTextField txtCol;

    private final JTextField txtProxy;
    private final JComboBox<Integer> comboThreads;
    private final JTextField txtDelay;
    private final JTextField txtTimeout;
    private final JTextField txtRetries;
    private final JTextField txtTimeSec;
    private final JCheckBox chkForceSsl;
    private final JCheckBox chkTor;
    private final JCheckBox chkHpp;

    private final JCheckBox chkBanner;
    private final JCheckBox chkCurrentDb;
    private final JCheckBox chkCurrentUser;
    private final JCheckBox chkIsDba;
    private final JCheckBox chkHostname;
    private final JCheckBox chkUsers;
    private final JCheckBox chkPasswords;
    private final JCheckBox chkPrivileges;
    private final JCheckBox chkRoles;
    private final JCheckBox chkDbs;
    private final JCheckBox chkTables;
    private final JCheckBox chkColumns;
    private final JCheckBox chkDump;

    private final JButton btnStartScan;
    private final JButton btnStopScan;
    private final JButton btnCopyCli;

    private final Runnable onPreSync;
    private final java.util.function.Consumer<Boolean> onSslToggled;
    private SqlmapTaskOptions currentOptions;

    public RequestConfigPanel(Runnable onStartScan, Runnable onStopScan) {
        this(onStartScan, onStopScan, null, null);
    }

    public RequestConfigPanel(Runnable onStartScan, Runnable onStopScan, Runnable onPreSync) {
        this(onStartScan, onStopScan, onPreSync, null);
    }

    public RequestConfigPanel(Runnable onStartScan, Runnable onStopScan, Runnable onPreSync, java.util.function.Consumer<Boolean> onSslToggled) {
        this.onPreSync = onPreSync;
        this.onSslToggled = onSslToggled;
        setLayout(new BorderLayout(0, 5));
        setBorder(new EmptyBorder(6, 6, 6, 6));

        currentOptions = new SqlmapTaskOptions();

        // Top Actions Bar (Buttons)
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        btnStartScan = SwingUtils.createStyledButton("Start Scan");
        btnStartScan.setFont(btnStartScan.getFont().deriveFont(Font.BOLD, 12));
        btnStartScan.setBackground(new Color(220, 245, 220));
        btnStartScan.addActionListener(e -> {
            if (onPreSync != null) onPreSync.run();
            applyUiToOptions();
            if (onStartScan != null) onStartScan.run();
        });

        btnStopScan = SwingUtils.createStyledButton("Stop / Cancel Scan");
        btnStopScan.setEnabled(false);
        btnStopScan.addActionListener(e -> {
            if (onStopScan != null) onStopScan.run();
        });

        btnCopyCli = SwingUtils.createStyledButton("Copy CLI Command");
        btnCopyCli.addActionListener(e -> copyCliCommand());

        actionPanel.add(btnStartScan);
        actionPanel.add(btnStopScan);
        actionPanel.add(btnCopyCli);
        add(actionPanel, BorderLayout.NORTH);

        // Scrollable Options Content
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        // 1. Presets Panel
        JPanel presetsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        presetsPanel.setBorder(new CompoundBorder(new TitledBorder("Quick Presets"), new EmptyBorder(2, 4, 4, 4)));

        JButton btnFast = SwingUtils.createStyledButton("Fast Detection");
        btnFast.addActionListener(e -> applyPresetFast());
        JButton btnStd = SwingUtils.createStyledButton("Standard Audit");
        btnStd.addActionListener(e -> applyPresetStandard());
        JButton btnDeep = SwingUtils.createStyledButton("Thorough");
        btnDeep.addActionListener(e -> applyPresetThorough());
        JButton btnWaf = SwingUtils.createStyledButton("WAF Bypass");
        btnWaf.addActionListener(e -> applyPresetWaf());

        presetsPanel.add(btnFast);
        presetsPanel.add(btnStd);
        presetsPanel.add(btnDeep);
        presetsPanel.add(btnWaf);
        content.add(presetsPanel);

        // 2. Detection & Techniques Panel
        JPanel detectPanel = new JPanel(new GridLayout(7, 2, 4, 4));
        detectPanel.setBorder(new CompoundBorder(new TitledBorder("Detection & Techniques"), new EmptyBorder(4, 6, 4, 6)));

        detectPanel.add(new JLabel("Test Parameter (-p):"));
        txtParam = new JTextField();
        detectPanel.add(txtParam);

        detectPanel.add(new JLabel("Detection Level (1-5):"));
        comboLevel = new JComboBox<>(new Integer[]{1, 2, 3, 4, 5});
        detectPanel.add(comboLevel);

        detectPanel.add(new JLabel("Risk Level (1-3):"));
        comboRisk = new JComboBox<>(new Integer[]{1, 2, 3});
        detectPanel.add(comboRisk);

        detectPanel.add(new JLabel("Techniques (BEUSTQ):"));
        txtTechnique = new JTextField("BEUSTQ");
        detectPanel.add(txtTechnique);

        detectPanel.add(new JLabel("Time-Sec (--time-sec):"));
        txtTimeSec = new JTextField("5");
        txtTimeSec.setToolTipText("Seconds to delay the DBMS response for time-based blind attacks (--time-sec, default 5)");
        detectPanel.add(txtTimeSec);

        detectPanel.add(new JLabel("Back-end DBMS:"));
        comboDbms = new JComboBox<>(new String[]{"", "MySQL", "PostgreSQL", "Oracle", "Microsoft SQL Server", "SQLite", "MariaDB"});
        comboDbms.setEditable(true);
        detectPanel.add(comboDbms);

        detectPanel.add(new JLabel("Tamper Scripts:"));
        tamperDropdown = new MultiSelectTamperDropdown_littlespidy();
        detectPanel.add(tamperDropdown);

        content.add(detectPanel);

        // 3. Headers Panel
        JPanel headerPanel = new JPanel(new BorderLayout(4, 4));
        headerPanel.setBorder(new CompoundBorder(new TitledBorder("Headers"), new EmptyBorder(4, 6, 6, 6)));

        JPanel topHeaderRow = new JPanel(new BorderLayout(6, 0));
        topHeaderRow.add(new JLabel("Headers:"), BorderLayout.WEST);
        headerDropdown = new MultiSelectHeaderDropdown_littlespidy();
        headerDropdown.setOnSelectionChanged(this::updateHeaderSummary);
        topHeaderRow.add(headerDropdown, BorderLayout.CENTER);
        headerPanel.add(topHeaderRow, BorderLayout.NORTH);

        lblHeaderSummary = new JLabel("Selected: None");
        lblHeaderSummary.setFont(lblHeaderSummary.getFont().deriveFont(Font.PLAIN, 11));
        lblHeaderSummary.setForeground(Color.GRAY);
        headerPanel.add(lblHeaderSummary, BorderLayout.SOUTH);

        content.add(headerPanel);

        // 4. Target Specific Resources (Optional -D, -T, -C)
        JPanel targetPanel = new JPanel(new GridLayout(3, 2, 4, 4));
        targetPanel.setBorder(new CompoundBorder(new TitledBorder("Target Specific Resources (Optional)"), new EmptyBorder(4, 6, 4, 6)));

        targetPanel.add(new JLabel("Database (-D):"));
        txtDb = new JTextField();
        txtDb.setToolTipText("Target specific database name");
        targetPanel.add(txtDb);

        targetPanel.add(new JLabel("Table (-T):"));
        txtTbl = new JTextField();
        txtTbl.setToolTipText("Target specific table name");
        targetPanel.add(txtTbl);

        targetPanel.add(new JLabel("Column (-C):"));
        txtCol = new JTextField();
        txtCol.setToolTipText("Target specific column(s) (comma-separated)");
        targetPanel.add(txtCol);

        content.add(targetPanel);

        // 5. Timing & Network Panel
        JPanel netPanel = new JPanel(new GridLayout(6, 2, 4, 4));
        netPanel.setBorder(new CompoundBorder(new TitledBorder("Timing & Network"), new EmptyBorder(4, 6, 4, 6)));

        netPanel.add(new JLabel("Proxy (--proxy):"));
        txtProxy = new JTextField(currentOptions.getProxy());
        txtProxy.setToolTipText("HTTP proxy URL (e.g. http://127.0.0.1:8080). Leave blank to disable.");
        netPanel.add(txtProxy);

        netPanel.add(new JLabel("Concurrent Threads:"));
        comboThreads = new JComboBox<>(new Integer[]{1, 2, 3, 4, 5, 8, 10});
        netPanel.add(comboThreads);

        netPanel.add(new JLabel("Delay (sec):"));
        txtDelay = new JTextField("0");
        netPanel.add(txtDelay);

        netPanel.add(new JLabel("Timeout (sec):"));
        txtTimeout = new JTextField("30");
        netPanel.add(txtTimeout);

        txtRetries = new JTextField("3");
        txtOs = new JTextField();

        chkForceSsl = new JCheckBox("Use HTTPS (--force-ssl)");
        chkForceSsl.setToolTipText("Force usage of SSL/HTTPS protocol for target requests");
        chkForceSsl.addActionListener(e -> onForceSslToggled());

        chkTor = new JCheckBox("Use Tor Socks5");
        chkHpp = new JCheckBox("HTTP Parameter Pollution (HPP)");
        netPanel.add(chkForceSsl);
        netPanel.add(chkTor);
        netPanel.add(chkHpp);
        netPanel.add(new JLabel());

        content.add(netPanel);

        // 4. Enumeration Targets Panel
        JPanel enumPanel = new JPanel(new GridLayout(7, 2, 2, 2));
        enumPanel.setBorder(new CompoundBorder(new TitledBorder("Enumeration Targets"), new EmptyBorder(4, 6, 4, 6)));

        chkBanner = new JCheckBox("Banner (-b)", true);
        chkCurrentDb = new JCheckBox("Current Database");
        chkCurrentUser = new JCheckBox("Current User");
        chkIsDba = new JCheckBox("Is DBA?");
        chkHostname = new JCheckBox("Hostname");
        chkUsers = new JCheckBox("Enumerate Users");
        chkPasswords = new JCheckBox("Password Hashes");
        chkPrivileges = new JCheckBox("Privileges");
        chkRoles = new JCheckBox("Roles");
        chkDbs = new JCheckBox("Enumerate Databases");
        chkTables = new JCheckBox("Enumerate Tables");
        chkColumns = new JCheckBox("Enumerate Columns");
        chkDump = new JCheckBox("Dump Table Data");

        enumPanel.add(chkBanner);
        enumPanel.add(chkCurrentDb);
        enumPanel.add(chkCurrentUser);
        enumPanel.add(chkIsDba);
        enumPanel.add(chkHostname);
        enumPanel.add(chkUsers);
        enumPanel.add(chkPasswords);
        enumPanel.add(chkPrivileges);
        enumPanel.add(chkRoles);
        enumPanel.add(chkDbs);
        enumPanel.add(chkTables);
        enumPanel.add(chkColumns);
        enumPanel.add(chkDump);

        content.add(enumPanel);

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);
    }

    public void loadOptions(SqlmapTaskOptions options) {
        if (options == null) return;
        this.currentOptions = options;

        txtParam.setText(options.getTestParameter());
        comboLevel.setSelectedItem(options.getLevel());
        comboRisk.setSelectedItem(options.getRisk());
        txtTechnique.setText(options.getTechnique());
        txtTimeSec.setText(String.valueOf(options.getTimeSec() > 0 ? options.getTimeSec() : 5));
        comboDbms.setSelectedItem(options.getDbms());
        txtOs.setText(options.getOs());
        tamperDropdown.setText(options.getTamper());
        txtDb.setText(options.getDb());
        txtTbl.setText(options.getTbl());
        txtCol.setText(options.getCol());

        txtProxy.setText(options.getProxy() != null ? options.getProxy() : "http://127.0.0.1:8080");

        comboThreads.setSelectedItem(options.getThreads());
        txtDelay.setText(String.valueOf(options.getDelay()));
        txtTimeout.setText(String.valueOf(options.getTimeout()));
        txtRetries.setText(String.valueOf(options.getRetries()));
        chkTor.setSelected(options.isTor());
        chkHpp.setSelected(options.isHpp());
        boolean isHttps = options.isForceSsl() || (options.getUrl() != null && options.getUrl().toLowerCase().startsWith("https://"));
        chkForceSsl.setSelected(isHttps);

        chkBanner.setSelected(options.isGetBanner());
        chkCurrentDb.setSelected(options.isGetCurrentDb());
        chkCurrentUser.setSelected(options.isGetCurrentUser());
        chkIsDba.setSelected(options.isDba());
        chkHostname.setSelected(options.isGetHostname());
        chkUsers.setSelected(options.isGetUsers());
        chkPasswords.setSelected(options.isGetPasswordHashes());
        chkPrivileges.setSelected(options.isGetPrivileges());
        chkRoles.setSelected(options.isGetRoles());
        chkDbs.setSelected(options.isGetDbs());
        chkTables.setSelected(options.isGetTables());
        chkColumns.setSelected(options.isGetColumns());
        chkDump.setSelected(options.isDumpTable());

        // Synchronize selected headers in headerDropdown
        java.util.Set<String> activeHeaders = new java.util.LinkedHashSet<>();
        if (options.getCookie() != null && !options.getCookie().isBlank()) {
            activeHeaders.add("Cookie");
        }
        if (options.getAgent() != null && !options.getAgent().isBlank()) {
            activeHeaders.add("User-Agent");
        }
        if (options.getReferer() != null && !options.getReferer().isBlank()) {
            activeHeaders.add("Referer");
        }
        if (options.getHeaders() != null && !options.getHeaders().isBlank()) {
            String[] lines = options.getHeaders().split("\r?\n");
            for (String line : lines) {
                int c = line.indexOf(':');
                if (c > 0) {
                    activeHeaders.add(line.substring(0, c).trim());
                }
            }
        }
        if (!activeHeaders.isEmpty()) {
            headerDropdown.setSelectedHeaders(activeHeaders);
        }
        updateHeaderSummary();
    }

    public void setRequestHeaders(java.util.Map<String, String> headers) {
        headerDropdown.setRequestHeaders(headers);
        updateHeaderSummary();
    }

    private void updateHeaderSummary() {
        java.util.Set<String> selected = headerDropdown.getSelectedHeaderNames();
        if (selected.isEmpty()) {
            lblHeaderSummary.setText("Selected: None");
            lblHeaderSummary.setToolTipText("No headers selected (requests will be sent without extra headers).");
            lblHeaderSummary.setForeground(Color.GRAY);
        } else {
            lblHeaderSummary.setText("Selected (" + selected.size() + ")");
            lblHeaderSummary.setToolTipText("Active headers: " + String.join(", ", selected));
            lblHeaderSummary.setForeground(new Color(0, 110, 0));
        }
    }

    public SqlmapTaskOptions applyUiToOptions() {
        if (currentOptions == null) {
            currentOptions = new SqlmapTaskOptions();
        }

        // Request Headers & Authentication from multi-select dropdown
        currentOptions.setCookie(headerDropdown.getSelectedCookie());
        currentOptions.setAgent(headerDropdown.getSelectedAgent());
        currentOptions.setReferer(headerDropdown.getSelectedReferer());
        currentOptions.setHeaders(headerDropdown.getSelectedHeadersString());

        currentOptions.setProxy(txtProxy.getText().trim());

        currentOptions.setTestParameter(txtParam.getText().trim());
        currentOptions.setLevel((Integer) comboLevel.getSelectedItem());
        currentOptions.setRisk((Integer) comboRisk.getSelectedItem());
        currentOptions.setTechnique(txtTechnique.getText().trim());
        try {
            currentOptions.setTimeSec(Integer.parseInt(txtTimeSec.getText().trim()));
        } catch (Exception ignored) {
            currentOptions.setTimeSec(5);
        }
        currentOptions.setDbms((String) comboDbms.getSelectedItem());
        currentOptions.setOs(txtOs.getText().trim());
        currentOptions.setTamper(tamperDropdown.getText());
        currentOptions.setDb(txtDb.getText().trim());
        currentOptions.setTbl(txtTbl.getText().trim());
        currentOptions.setCol(txtCol.getText().trim());

        currentOptions.setThreads((Integer) comboThreads.getSelectedItem());
        try { currentOptions.setDelay(Integer.parseInt(txtDelay.getText().trim())); } catch (Exception ignored) {}
        try { currentOptions.setTimeout(Integer.parseInt(txtTimeout.getText().trim())); } catch (Exception ignored) {}
        try { currentOptions.setRetries(Integer.parseInt(txtRetries.getText().trim())); } catch (Exception ignored) {}
        currentOptions.setTor(chkTor.isSelected());
        currentOptions.setHpp(chkHpp.isSelected());

        boolean forceSsl = chkForceSsl.isSelected();
        currentOptions.setForceSsl(forceSsl);
        String currentUrl = currentOptions.getUrl();
        if (currentUrl != null && !currentUrl.isBlank()) {
            if (forceSsl && currentUrl.startsWith("http://")) {
                currentOptions.setUrl("https://" + currentUrl.substring(7));
            } else if (!forceSsl && currentUrl.startsWith("https://")) {
                currentOptions.setUrl("http://" + currentUrl.substring(8));
            }
        }

        currentOptions.setGetBanner(chkBanner.isSelected());
        currentOptions.setGetCurrentDb(chkCurrentDb.isSelected());
        currentOptions.setGetCurrentUser(chkCurrentUser.isSelected());
        currentOptions.setDba(chkIsDba.isSelected());
        currentOptions.setGetHostname(chkHostname.isSelected());
        currentOptions.setGetUsers(chkUsers.isSelected());
        currentOptions.setGetPasswordHashes(chkPasswords.isSelected());
        currentOptions.setGetPrivileges(chkPrivileges.isSelected());
        currentOptions.setGetRoles(chkRoles.isSelected());
        currentOptions.setGetDbs(chkDbs.isSelected());
        currentOptions.setGetTables(chkTables.isSelected());
        currentOptions.setGetColumns(chkColumns.isSelected());
        currentOptions.setDumpTable(chkDump.isSelected());

        return currentOptions;
    }

    public void setScanningState(boolean scanning) {
        btnStartScan.setEnabled(!scanning);
        btnStopScan.setEnabled(scanning);
    }

    private void applyPresetFast() {
        comboLevel.setSelectedItem(1);
        comboRisk.setSelectedItem(1);
        txtTechnique.setText("BEUSTQ");
        tamperDropdown.setText("");
        comboThreads.setSelectedItem(1);
    }

    private void applyPresetStandard() {
        comboLevel.setSelectedItem(2);
        comboRisk.setSelectedItem(2);
        txtTechnique.setText("BEU");
        comboThreads.setSelectedItem(2);
    }

    private void applyPresetThorough() {
        comboLevel.setSelectedItem(5);
        comboRisk.setSelectedItem(3);
        txtTechnique.setText("BEUSTQ");
        comboThreads.setSelectedItem(3);
        chkCurrentDb.setSelected(true);
        chkCurrentUser.setSelected(true);
        chkIsDba.setSelected(true);
    }

    private void applyPresetWaf() {
        comboLevel.setSelectedItem(3);
        comboRisk.setSelectedItem(2);
        tamperDropdown.setText("space2comment,between,randomcase");
        chkHpp.setSelected(true);
    }

    private void copyCliCommand() {
        if (onPreSync != null) onPreSync.run();
        applyUiToOptions();
        String cmd = currentOptions.buildCommandLine();
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(cmd), null);
        CliCommandDialog_littlespidy.showCli(this, cmd);
    }

    public JTextField getTxtTimeSecForTest() {
        return txtTimeSec;
    }

    public JCheckBox getChkForceSslForTest() {
        return chkForceSsl;
    }

    private void onForceSslToggled() {
        if (currentOptions == null) return;
        boolean forceSsl = chkForceSsl.isSelected();
        currentOptions.setForceSsl(forceSsl);
        String currentUrl = currentOptions.getUrl();
        if (currentUrl != null && !currentUrl.isBlank()) {
            if (forceSsl && currentUrl.startsWith("http://")) {
                currentOptions.setUrl("https://" + currentUrl.substring(7));
            } else if (!forceSsl && currentUrl.startsWith("https://")) {
                currentOptions.setUrl("http://" + currentUrl.substring(8));
            }
        }
        if (onSslToggled != null) {
            onSslToggled.accept(forceSsl);
        }
    }
}
