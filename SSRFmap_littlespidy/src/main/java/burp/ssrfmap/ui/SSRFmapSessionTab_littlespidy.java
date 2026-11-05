// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.ssrfmap.engine.CollaboratorManager_littlespidy;
import burp.ssrfmap.engine.SSRFScanEngine_littlespidy;
import burp.ssrfmap.model.SSRFModuleCategory_littlespidy;
import burp.ssrfmap.model.SSRFResultEntry_littlespidy;
import burp.ssrfmap.modules.SSRFPayloadItem_littlespidy;
import burp.ssrfmap.modules.SSRFPayloadManager_littlespidy;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.table.TableRowSorter;

public class SSRFmapSessionTab_littlespidy extends JPanel {
    private final MontoyaApi api;
    private final CollaboratorManager_littlespidy collaboratorManager;

    private final JTextField hostField;
    private final JTextField portField;
    private final JComboBox<String> protocolCombo;

    private final MarkerRequestEditor_littlespidy requestEditor;
    private final SSRFTableModel_littlespidy tableModel;
    private final JTable resultsTable;
    private final TableRowSorter<SSRFTableModel_littlespidy> tableSorter;

    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;
    private final JTextArea collabViewer;

    private final JTextField concurrencyField;
    private final JTextField delayField;
    private final JCheckBox useCollaboratorCheck;

    private final JButton pauseAttackBtn;
    private final JButton stopAttackBtn;
    private final JProgressBar progressBar;
    private final JLabel progressStatusLabel;

    private final JButton filterDropdownBtn;
    private final Set<String> activeFilterTypes = new HashSet<>();
    private final List<JCheckBox> filterCheckboxes = new ArrayList<>();

    private SSRFScanEngine_littlespidy currentEngine;

    public SSRFmapSessionTab_littlespidy(
            MontoyaApi api,
            CollaboratorManager_littlespidy collaboratorManager,
            HttpRequestResponse initialReqResp) {
        super(new BorderLayout());
        this.api = api;
        this.collaboratorManager = collaboratorManager;

        // --- 1. Left Side: Target, Request, Action Buttons, Settings ---
        JPanel leftPanel = new JPanel(new BorderLayout(0, 4));
        leftPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        // Target Bar
        JPanel targetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        targetPanel.setBorder(BorderFactory.createTitledBorder("Target Configuration"));
        targetPanel.add(new JLabel("Host:"));
        hostField = new JTextField(16);
        targetPanel.add(hostField);

        targetPanel.add(new JLabel("Port:"));
        portField = new JTextField(4);
        targetPanel.add(portField);

        targetPanel.add(new JLabel("Protocol:"));
        protocolCombo = new JComboBox<>(new String[]{"HTTPS", "HTTP"});
        targetPanel.add(protocolCombo);

        if (initialReqResp != null && initialReqResp.request() != null && initialReqResp.request().httpService() != null) {
            HttpService svc = initialReqResp.request().httpService();
            hostField.setText(svc.host());
            portField.setText(String.valueOf(svc.port()));
            protocolCombo.setSelectedItem(svc.secure() ? "HTTPS" : "HTTP");
        } else {
            hostField.setText("127.0.0.1");
            portField.setText("443");
            protocolCombo.setSelectedItem("HTTPS");
        }

        // Request Editor with Markers
        requestEditor = new MarkerRequestEditor_littlespidy();
        requestEditor.setPreferredSize(new Dimension(380, 220));
        if (initialReqResp != null && initialReqResp.request() != null) {
            requestEditor.setRequestText(initialReqResp.request().toString());
        }

        JPanel topConfigPanel = new JPanel(new BorderLayout(0, 4));
        topConfigPanel.add(targetPanel, BorderLayout.NORTH);
        topConfigPanel.add(requestEditor, BorderLayout.CENTER);

        // Scrollable Options: Categorized Attack Buttons
        JPanel actionPanelsContainer = new JPanel();
        actionPanelsContainer.setLayout(new BoxLayout(actionPanelsContainer, BoxLayout.Y_AXIS));

        // 1. Protocol Schemes (Only [All Protocols] button)
        JPanel protocolsGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        protocolsGroup.setBorder(BorderFactory.createTitledBorder("Protocol Schemes (file, dict, sftp, tftp, ldap, smtp, gopher, http, https)"));
        JButton allProtocolsBtn = new JButton("Run All Protocols");
        allProtocolsBtn.setFont(allProtocolsBtn.getFont().deriveFont(Font.BOLD));
        allProtocolsBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getAllProtocolPayloads(), "All Protocols"));
        protocolsGroup.add(allProtocolsBtn);
        actionPanelsContainer.add(protocolsGroup);

        // 2. Cloud Metadata Group (Individual buttons + All Clouds)
        JPanel cloudGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        cloudGroup.setBorder(BorderFactory.createTitledBorder("Cloud Metadata Attacks"));

        JButton awsBtn = new JButton("AWS");
        awsBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getCloudPayloads("aws"), "AWS Metadata"));
        cloudGroup.add(awsBtn);

        JButton gcpBtn = new JButton("GCP");
        gcpBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getCloudPayloads("gcp"), "Google Cloud Metadata"));
        cloudGroup.add(gcpBtn);

        JButton azureBtn = new JButton("Azure");
        azureBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getCloudPayloads("azure"), "Azure Metadata"));
        cloudGroup.add(azureBtn);

        JButton alibabaBtn = new JButton("Alibaba");
        alibabaBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getCloudPayloads("alibaba"), "Alibaba Metadata"));
        cloudGroup.add(alibabaBtn);

        JButton doBtn = new JButton("DigitalOcean");
        doBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getCloudPayloads("digitalocean"), "DigitalOcean Metadata"));
        cloudGroup.add(doBtn);

        JButton allCloudsBtn = new JButton("Run All Clouds");
        allCloudsBtn.setFont(allCloudsBtn.getFont().deriveFont(Font.BOLD));
        allCloudsBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getAllCloudPayloads(), "All Cloud Metadata"));
        cloudGroup.add(allCloudsBtn);

        actionPanelsContainer.add(cloudGroup);

        // 3. SSRF Service Exploits Group (Individual buttons + All Services)
        JPanel servicesGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        servicesGroup.setBorder(BorderFactory.createTitledBorder("SSRF Service Exploits & Probes"));

        JButton redisBtn = new JButton("Redis");
        redisBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getServicePayloads("redis"), "Redis Exploit"));
        servicesGroup.add(redisBtn);

        JButton dockerBtn = new JButton("Docker");
        dockerBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getServicePayloads("docker"), "Docker API"));
        servicesGroup.add(dockerBtn);

        JButton fastcgiBtn = new JButton("FastCGI");
        fastcgiBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getServicePayloads("fastcgi"), "FastCGI Handshake"));
        servicesGroup.add(fastcgiBtn);

        JButton readfilesBtn = new JButton("ReadFiles");
        readfilesBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getServicePayloads("readfiles"), "ReadFiles"));
        servicesGroup.add(readfilesBtn);

        JButton memcachedBtn = new JButton("Memcached");
        memcachedBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getServicePayloads("memcached"), "Memcached"));
        servicesGroup.add(memcachedBtn);

        JButton portscanBtn = new JButton("PortScan");
        portscanBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getServicePayloads("portscan"), "Port Scanner"));
        servicesGroup.add(portscanBtn);

        JButton allServicesBtn = new JButton("Run All Services");
        allServicesBtn.setFont(allServicesBtn.getFont().deriveFont(Font.BOLD));
        allServicesBtn.addActionListener(e -> launchAttack(SSRFPayloadManager_littlespidy.getInstance().getAllServicePayloads(), "All Service Exploits"));
        servicesGroup.add(allServicesBtn);

        actionPanelsContainer.add(servicesGroup);

        // 4. Dedicated Tools & Collaborator Group
        JPanel toolsGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        toolsGroup.setBorder(BorderFactory.createTitledBorder("Collaborator & Utilities"));

        JButton collabCheckBtn = new JButton("Collaborator Probe");
        collabCheckBtn.setFont(collabCheckBtn.getFont().deriveFont(Font.BOLD));
        collabCheckBtn.addActionListener(e -> runCollaboratorProbe());
        toolsGroup.add(collabCheckBtn);

        JButton viewPayloadsBtn = new JButton("View Payloads");
        viewPayloadsBtn.addActionListener(e -> {
            Frame topFrame = (Frame) SwingUtilities.getWindowAncestor(this);
            PayloadViewerDialog_littlespidy dialog = new PayloadViewerDialog_littlespidy(topFrame);
            dialog.setVisible(true);
        });
        toolsGroup.add(viewPayloadsBtn);

        actionPanelsContainer.add(toolsGroup);

        // 5. Execution Settings
        JPanel settingsGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        settingsGroup.setBorder(BorderFactory.createTitledBorder("Execution Settings"));
        settingsGroup.add(new JLabel("Threads:"));
        concurrencyField = new JTextField("5", 3);
        settingsGroup.add(concurrencyField);

        settingsGroup.add(new JLabel("Delay (ms):"));
        delayField = new JTextField("50", 4);
        settingsGroup.add(delayField);

        useCollaboratorCheck = new JCheckBox("Burp Collaborator", collaboratorManager.isAvailable());
        useCollaboratorCheck.setEnabled(collaboratorManager.isAvailable());
        settingsGroup.add(useCollaboratorCheck);
        actionPanelsContainer.add(settingsGroup);

        JScrollPane optionsScroll = new JScrollPane(actionPanelsContainer);
        optionsScroll.setPreferredSize(new Dimension(380, 240));

        // Progress & Execution Controls
        JPanel actionPanel = new JPanel(new BorderLayout(4, 4));
        actionPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel controlButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        pauseAttackBtn = new JButton("Pause");
        pauseAttackBtn.setEnabled(false);
        pauseAttackBtn.addActionListener(e -> togglePause());

        stopAttackBtn = new JButton("Stop");
        stopAttackBtn.setEnabled(false);
        stopAttackBtn.addActionListener(e -> stopAttack());

        controlButtonsPanel.add(pauseAttackBtn);
        controlButtonsPanel.add(stopAttackBtn);

        JPanel progressStatusPanel = new JPanel(new BorderLayout(4, 2));
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        progressStatusLabel = new JLabel("Status: Idle");

        progressStatusPanel.add(progressBar, BorderLayout.CENTER);
        progressStatusPanel.add(progressStatusLabel, BorderLayout.SOUTH);

        actionPanel.add(controlButtonsPanel, BorderLayout.NORTH);
        actionPanel.add(progressStatusPanel, BorderLayout.CENTER);

        JSplitPane leftSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topConfigPanel, optionsScroll);
        leftSplit.setResizeWeight(0.5);

        leftPanel.add(leftSplit, BorderLayout.CENTER);
        leftPanel.add(actionPanel, BorderLayout.SOUTH);

        // --- 2. Right Side: Results Table + Montoya Traffic Viewers ---
        JPanel rightPanel = new JPanel(new BorderLayout(0, 4));
        rightPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        // Filter Bar with Multi-Select Dropdown
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filterBar.add(new JLabel("Search:"));
        JTextField filterInput = new JTextField(16);
        filterBar.add(filterInput);

        filterDropdownBtn = new JButton("Attack Filter (All Types)");
        setupMultiSelectFilterPopup();
        filterBar.add(filterDropdownBtn);

        JButton clearTableBtn = new JButton("Clear Results");
        filterBar.add(clearTableBtn);

        tableModel = new SSRFTableModel_littlespidy();
        resultsTable = new JTable(tableModel);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tableSorter = new TableRowSorter<>(tableModel);
        resultsTable.setRowSorter(tableSorter);

        filterInput.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilters(filterInput.getText()); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilters(filterInput.getText()); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilters(filterInput.getText()); }
        });

        clearTableBtn.addActionListener(e -> {
            tableModel.clear();
            clearViewers();
        });

        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.setPreferredSize(new Dimension(500, 240));

        JPanel topTablePanel = new JPanel(new BorderLayout(0, 4));
        topTablePanel.add(filterBar, BorderLayout.NORTH);
        topTablePanel.add(tableScroll, BorderLayout.CENTER);

        // Lower Tabbed Pane: Raw Request & Response, Collaborator Details (DIFF REMOVED)
        JTabbedPane viewerTabs = new JTabbedPane();

        requestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        collabViewer = new JTextArea();
        collabViewer.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        collabViewer.setEditable(false);

        JSplitPane reqRespSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                requestViewer.uiComponent(),
                responseViewer.uiComponent()
        );
        reqRespSplit.setResizeWeight(0.5);

        viewerTabs.addTab("Raw Request & Response", reqRespSplit);
        viewerTabs.addTab("Collaborator Details", new JScrollPane(collabViewer));

        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultsTable.getSelectedRow();
                if (selectedRow != -1) {
                    int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
                    displayEntry(tableModel.getEntry(modelRow));
                }
            }
        });

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topTablePanel, viewerTabs);
        rightSplit.setResizeWeight(0.5);
        rightPanel.add(rightSplit, BorderLayout.CENTER);

        // Main Horizontal Split Pane
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        mainSplit.setResizeWeight(0.42);
        add(mainSplit, BorderLayout.CENTER);
    }

    private void setupMultiSelectFilterPopup() {
        String[] types = new String[]{
            "baseline", "file", "dict", "sftp", "tftp", "ldap", "smtp", "gopher", "http", "https",
            "aws", "gcp", "azure", "alibaba", "digitalocean",
            "redis", "docker", "fastcgi", "readfiles", "memcached", "portscan", "collaborator"
        };

        for (String t : types) {
            activeFilterTypes.add(t);
        }

        JPopupMenu popup = new JPopupMenu();

        JPanel checkAllPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton selectAllBtn = new JButton("Select All");
        JButton deselectAllBtn = new JButton("Clear All");

        selectAllBtn.addActionListener(e -> {
            for (JCheckBox cb : filterCheckboxes) {
                cb.setSelected(true);
                activeFilterTypes.add(cb.getText());
            }
            updateFilterButtonText();
            applyFilters("");
        });

        deselectAllBtn.addActionListener(e -> {
            for (JCheckBox cb : filterCheckboxes) {
                cb.setSelected(false);
                activeFilterTypes.remove(cb.getText());
            }
            updateFilterButtonText();
            applyFilters("");
        });

        checkAllPanel.add(selectAllBtn);
        checkAllPanel.add(deselectAllBtn);
        popup.add(checkAllPanel);
        popup.addSeparator();

        JPanel itemsGrid = new JPanel(new GridLayout(0, 2, 4, 2));
        for (String type : types) {
            JCheckBox cb = new JCheckBox(type, true);
            filterCheckboxes.add(cb);
            cb.addActionListener(e -> {
                if (cb.isSelected()) {
                    activeFilterTypes.add(type);
                } else {
                    activeFilterTypes.remove(type);
                }
                updateFilterButtonText();
                applyFilters("");
            });
            itemsGrid.add(cb);
        }

        popup.add(itemsGrid);

        filterDropdownBtn.addActionListener(e -> {
            popup.show(filterDropdownBtn, 0, filterDropdownBtn.getHeight());
        });
    }

    private void updateFilterButtonText() {
        int total = filterCheckboxes.size();
        int active = activeFilterTypes.size();
        if (active == total) {
            filterDropdownBtn.setText("Attack Filter (All Types)");
        } else if (active == 0) {
            filterDropdownBtn.setText("Attack Filter (None)");
        } else {
            filterDropdownBtn.setText("Attack Filter (" + active + "/" + total + ")");
        }
    }

    private void applyFilters(String searchText) {
        List<RowFilter<SSRFTableModel_littlespidy, Integer>> filters = new ArrayList<>();

        if (!searchText.trim().isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(searchText.trim())));
        }

        if (activeFilterTypes.size() < filterCheckboxes.size()) {
            RowFilter<SSRFTableModel_littlespidy, Integer> typeFilter = new RowFilter<SSRFTableModel_littlespidy, Integer>() {
                @Override
                public boolean include(Entry<? extends SSRFTableModel_littlespidy, ? extends Integer> entry) {
                    Object moduleObj = entry.getValue(1);
                    if (moduleObj == null) return false;
                    String mod = moduleObj.toString().toLowerCase();
                    return activeFilterTypes.contains(mod);
                }
            };
            filters.add(typeFilter);
        }

        if (filters.isEmpty()) {
            tableSorter.setRowFilter(null);
        } else if (filters.size() == 1) {
            tableSorter.setRowFilter(filters.get(0));
        } else {
            tableSorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    private void displayEntry(SSRFResultEntry_littlespidy entry) {
        if (entry == null) {
            clearViewers();
            return;
        }

        HttpRequestResponse reqResp = entry.getHttpRequestResponse();
        if (reqResp != null) {
            if (reqResp.request() != null) {
                requestViewer.setRequest(reqResp.request());
            } else {
                requestViewer.setRequest(HttpRequest.httpRequest(""));
            }
            if (reqResp.response() != null) {
                responseViewer.setResponse(reqResp.response());
            } else {
                responseViewer.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(""));
            }
        } else {
            clearViewers();
        }

        String collabText = entry.getCollaboratorInteractionDetails();
        if (collabText == null || collabText.isEmpty()) {
            collabViewer.setText("Collaborator status: " + entry.getCollaboratorInfo());
        } else {
            collabViewer.setText(collabText);
        }
    }

    private void clearViewers() {
        requestViewer.setRequest(HttpRequest.httpRequest(""));
        responseViewer.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(""));
        collabViewer.setText("");
    }

    private void runCollaboratorProbe() {
        if (!requestEditor.hasMarker()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please highlight parameter value in the request editor and click 'Add Section Marker (§)' first.",
                    "Marker Required",
                    JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        SSRFPayloadItem_littlespidy collabItem = new SSRFPayloadItem_littlespidy(
                SSRFModuleCategory_littlespidy.PROTOCOL,
                "collaborator",
                "http://",
                "Collaborator Dedicated Out-Of-Band Probe",
                "http://{COLLABORATOR_HOST}/",
                Collections.emptyList(),
                true
        );

        launchAttack(Collections.singletonList(collabItem), "Collaborator Dedicated Probe");
    }

    private void launchAttack(List<SSRFPayloadItem_littlespidy> payloads, String attackLabel) {
        if (!requestEditor.hasMarker()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please highlight parameter value in the request editor and click 'Add Section Marker (§)' first.",
                    "Marker Required",
                    JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        if (payloads == null || payloads.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No payloads found for this category.", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String host = hostField.getText().trim();
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(this, "Invalid port number", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        boolean secure = "HTTPS".equalsIgnoreCase((String) protocolCombo.getSelectedItem());
        HttpService httpService = HttpService.httpService(host, port, secure);

        int concurrency = 5;
        try {
            concurrency = Integer.parseInt(concurrencyField.getText().trim());
        } catch (NumberFormatException ignored) {}

        int delay = 50;
        try {
            delay = Integer.parseInt(delayField.getText().trim());
        } catch (NumberFormatException ignored) {}

        boolean useCollab = useCollaboratorCheck.isSelected();

        // Note: Do not clear tableModel, append results to existing history
        pauseAttackBtn.setEnabled(true);
        pauseAttackBtn.setText("Pause");
        stopAttackBtn.setEnabled(true);
        progressBar.setValue(0);
        progressBar.setString("0 / " + payloads.size());
        progressStatusLabel.setText("Status: Launching " + attackLabel + " (" + payloads.size() + " payloads)...");

        currentEngine = new SSRFScanEngine_littlespidy(
                api,
                httpService,
                requestEditor,
                tableModel,
                collaboratorManager,
                payloads,
                concurrency,
                delay,
                useCollab,
                new SSRFScanEngine_littlespidy.ScanProgressListener() {
                    @Override
                    public void onProgress(int current, int total) {
                        SwingUtilities.invokeLater(() -> {
                            int pct = (int) (((double) current / total) * 100);
                            progressBar.setValue(pct);
                            progressBar.setString(current + " / " + total + " (" + pct + "%)");
                        });
                    }

                    @Override
                    public void onStatusChanged(String statusText) {
                        SwingUtilities.invokeLater(() -> progressStatusLabel.setText("Status: " + statusText));
                    }

                    @Override
                    public void onFinished() {
                        SwingUtilities.invokeLater(() -> {
                            pauseAttackBtn.setEnabled(false);
                            stopAttackBtn.setEnabled(false);
                        });
                    }
                }
        );

        currentEngine.start();
    }

    private void togglePause() {
        if (currentEngine == null) return;
        if (currentEngine.isPaused()) {
            currentEngine.resume();
            pauseAttackBtn.setText("Pause");
        } else {
            currentEngine.pause();
            pauseAttackBtn.setText("Resume");
        }
    }

    private void stopAttack() {
        if (currentEngine != null) {
            currentEngine.stop();
        }
    }
}
