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

    private final JTextField txtDb;
    private final JTextField txtTbl;
    private final JTextField txtCol;

    private final JComboBox<Integer> comboThreads;
    private final JTextField txtDelay;
    private final JTextField txtTimeout;
    private final JTextField txtRetries;
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

    private SqlmapTaskOptions currentOptions;

    public RequestConfigPanel(Runnable onStartScan, Runnable onStopScan) {
        setLayout(new BorderLayout(0, 5));
        setBorder(new EmptyBorder(6, 6, 6, 6));

        currentOptions = new SqlmapTaskOptions();

        // Top Actions Bar (Buttons)
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        btnStartScan = SwingUtils.createStyledButton("Start Scan");
        btnStartScan.setFont(btnStartScan.getFont().deriveFont(Font.BOLD, 12));
        btnStartScan.setBackground(new Color(220, 245, 220));
        btnStartScan.addActionListener(e -> {
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
        JPanel detectPanel = new JPanel(new GridLayout(6, 2, 4, 4));
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

        detectPanel.add(new JLabel("Back-end DBMS:"));
        comboDbms = new JComboBox<>(new String[]{"", "MySQL", "PostgreSQL", "Oracle", "Microsoft SQL Server", "SQLite", "MariaDB"});
        comboDbms.setEditable(true);
        detectPanel.add(comboDbms);

        detectPanel.add(new JLabel("Tamper Scripts:"));
        tamperDropdown = new MultiSelectTamperDropdown_littlespidy();
        detectPanel.add(tamperDropdown);

        content.add(detectPanel);

        // 3. Target Specific Resources (Optional -D, -T, -C)
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

        // 3. Timing & Network Panel
        JPanel netPanel = new JPanel(new GridLayout(4, 2, 4, 4));
        netPanel.setBorder(new CompoundBorder(new TitledBorder("Timing & Network"), new EmptyBorder(4, 6, 4, 6)));

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

        chkTor = new JCheckBox("Use Tor Socks5");
        chkHpp = new JCheckBox("HTTP Parameter Pollution (HPP)");
        netPanel.add(chkTor);
        netPanel.add(chkHpp);

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
        comboDbms.setSelectedItem(options.getDbms());
        txtOs.setText(options.getOs());
        tamperDropdown.setText(options.getTamper());
        txtDb.setText(options.getDb());
        txtTbl.setText(options.getTbl());
        txtCol.setText(options.getCol());

        comboThreads.setSelectedItem(options.getThreads());
        txtDelay.setText(String.valueOf(options.getDelay()));
        txtTimeout.setText(String.valueOf(options.getTimeout()));
        txtRetries.setText(String.valueOf(options.getRetries()));
        chkTor.setSelected(options.isTor());
        chkHpp.setSelected(options.isHpp());

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
    }

    public SqlmapTaskOptions applyUiToOptions() {
        if (currentOptions == null) {
            currentOptions = new SqlmapTaskOptions();
        }

        currentOptions.setTestParameter(txtParam.getText().trim());
        currentOptions.setLevel((Integer) comboLevel.getSelectedItem());
        currentOptions.setRisk((Integer) comboRisk.getSelectedItem());
        currentOptions.setTechnique(txtTechnique.getText().trim());
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
        applyUiToOptions();
        String cmd = currentOptions.buildCommandLine();
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(cmd), null);
        CliCommandDialog_littlespidy.showCli(this, cmd);
    }
}
