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
import burp.ssrfmap.model.SSRFResultEntry_littlespidy;
import burp.ssrfmap.modules.CloudMetadataModules_littlespidy;
import burp.ssrfmap.modules.ProtocolModules_littlespidy;
import burp.ssrfmap.modules.SSRFPayloadItem_littlespidy;
import burp.ssrfmap.modules.ServiceExploitModules_littlespidy;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
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
    private final JTextArea diffViewer;
    private final JTextArea collabViewer;

    private final Map<String, JCheckBox> protocolCheckboxes = new HashMap<>();
    private final Map<String, JCheckBox> cloudCheckboxes = new HashMap<>();
    private final Map<String, JCheckBox> serviceCheckboxes = new HashMap<>();

    private final JTextField concurrencyField;
    private final JTextField delayField;
    private final JCheckBox useCollaboratorCheck;
    private final JCheckBox useDiffCheck;

    private final JButton startAttackBtn;
    private final JButton pauseAttackBtn;
    private final JButton stopAttackBtn;
    private final JProgressBar progressBar;
    private final JLabel progressStatusLabel;

    private SSRFScanEngine_littlespidy currentEngine;

    public SSRFmapSessionTab_littlespidy(
            MontoyaApi api,
            CollaboratorManager_littlespidy collaboratorManager,
            HttpRequestResponse initialReqResp) {
        super(new BorderLayout());
        this.api = api;
        this.collaboratorManager = collaboratorManager;

        // --- 1. Left Side: Target, Request, Modules, Settings, Action controls ---
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

        // Populate initial target info
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

        // Scrollable Options: Modules & Settings
        JPanel optionsContainer = new JPanel();
        optionsContainer.setLayout(new BoxLayout(optionsContainer, BoxLayout.Y_AXIS));

        // Protocols Group (7 Requested Protocols)
        JPanel protocolsGroup = new JPanel(new GridLayout(4, 2, 4, 2));
        protocolsGroup.setBorder(BorderFactory.createTitledBorder("Protocol Schemes (7 Core Vectors)"));
        String[] protocols = new String[]{"file", "dict", "sftp", "tftp", "ldap", "smtp", "gopher"};
        for (String p : protocols) {
            JCheckBox cb = new JCheckBox(p + "://", true);
            protocolCheckboxes.put(p, cb);
            protocolsGroup.add(cb);
        }
        optionsContainer.add(protocolsGroup);

        // Cloud Metadata Group
        JPanel cloudGroup = new JPanel(new GridLayout(3, 2, 4, 2));
        cloudGroup.setBorder(BorderFactory.createTitledBorder("Cloud Metadata Services"));
        String[] clouds = new String[]{"aws", "gcp", "alibaba", "digitalocean", "azure"};
        for (String c : clouds) {
            JCheckBox cb = new JCheckBox(c.toUpperCase() + " Metadata", true);
            cloudCheckboxes.put(c, cb);
            cloudGroup.add(cb);
        }
        optionsContainer.add(cloudGroup);

        // Service Exploits Group
        JPanel servicesGroup = new JPanel(new GridLayout(3, 2, 4, 2));
        servicesGroup.setBorder(BorderFactory.createTitledBorder("SSRFmap Service Exploits"));
        String[] services = new String[]{"redis", "docker", "fastcgi", "readfiles", "memcached", "portscan"};
        for (String s : services) {
            JCheckBox cb = new JCheckBox(s.substring(0, 1).toUpperCase() + s.substring(1), !s.equals("portscan"));
            serviceCheckboxes.put(s, cb);
            servicesGroup.add(cb);
        }
        optionsContainer.add(servicesGroup);

        // Attack Settings Group
        JPanel settingsGroup = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        settingsGroup.setBorder(BorderFactory.createTitledBorder("Attack Settings"));
        settingsGroup.add(new JLabel("Threads:"));
        concurrencyField = new JTextField("5", 3);
        settingsGroup.add(concurrencyField);

        settingsGroup.add(new JLabel("Delay (ms):"));
        delayField = new JTextField("50", 4);
        settingsGroup.add(delayField);

        useCollaboratorCheck = new JCheckBox("Burp Collaborator", collaboratorManager.isAvailable());
        useCollaboratorCheck.setEnabled(collaboratorManager.isAvailable());
        settingsGroup.add(useCollaboratorCheck);

        useDiffCheck = new JCheckBox("Baseline Diffing", true);
        settingsGroup.add(useDiffCheck);
        optionsContainer.add(settingsGroup);

        JScrollPane optionsScroll = new JScrollPane(optionsContainer);
        optionsScroll.setPreferredSize(new Dimension(380, 200));

        // Action Buttons & Progress Bar
        JPanel actionPanel = new JPanel(new BorderLayout(4, 4));
        actionPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        startAttackBtn = new JButton("Start Attack");
        startAttackBtn.addActionListener(e -> startAttack());

        pauseAttackBtn = new JButton("Pause");
        pauseAttackBtn.setEnabled(false);
        pauseAttackBtn.addActionListener(e -> togglePause());

        stopAttackBtn = new JButton("Stop");
        stopAttackBtn.setEnabled(false);
        stopAttackBtn.addActionListener(e -> stopAttack());

        buttonsPanel.add(startAttackBtn);
        buttonsPanel.add(pauseAttackBtn);
        buttonsPanel.add(stopAttackBtn);

        JPanel progressStatusPanel = new JPanel(new BorderLayout(4, 2));
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        progressStatusLabel = new JLabel("Status: Idle");

        progressStatusPanel.add(progressBar, BorderLayout.CENTER);
        progressStatusPanel.add(progressStatusLabel, BorderLayout.SOUTH);

        actionPanel.add(buttonsPanel, BorderLayout.NORTH);
        actionPanel.add(progressStatusPanel, BorderLayout.CENTER);

        JSplitPane leftSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topConfigPanel, optionsScroll);
        leftSplit.setResizeWeight(0.55);

        leftPanel.add(leftSplit, BorderLayout.CENTER);
        leftPanel.add(actionPanel, BorderLayout.SOUTH);

        // --- 2. Right Side: Results Table + Montoya Traffic Viewers ---
        JPanel rightPanel = new JPanel(new BorderLayout(0, 4));
        rightPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        // Filter Bar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filterBar.add(new JLabel("Filter:"));
        JTextField filterInput = new JTextField(24);
        filterBar.add(filterInput);

        JButton clearTableBtn = new JButton("Clear Results");
        filterBar.add(clearTableBtn);

        tableModel = new SSRFTableModel_littlespidy();
        resultsTable = new JTable(tableModel);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tableSorter = new TableRowSorter<>(tableModel);
        resultsTable.setRowSorter(tableSorter);

        filterInput.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private void updateFilter() {
                String text = filterInput.getText();
                if (text.trim().isEmpty()) {
                    tableSorter.setRowFilter(null);
                } else {
                    tableSorter.setRowFilter(RowFilter.regexFilter("(?i)" + PatternQuote(text)));
                }
            }
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateFilter(); }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateFilter(); }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateFilter(); }
        });

        clearTableBtn.addActionListener(e -> {
            tableModel.clear();
            clearViewers();
        });

        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.setPreferredSize(new Dimension(500, 220));

        JPanel topTablePanel = new JPanel(new BorderLayout(0, 4));
        topTablePanel.add(filterBar, BorderLayout.NORTH);
        topTablePanel.add(tableScroll, BorderLayout.CENTER);

        // Lower Tabbed Pane: Raw Request, Raw Response, Diff, Collaborator
        JTabbedPane viewerTabs = new JTabbedPane();

        requestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        diffViewer = new JTextArea();
        diffViewer.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        diffViewer.setEditable(false);

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
        viewerTabs.addTab("Response Diff Analysis", new JScrollPane(diffViewer));
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

        diffViewer.setText(entry.getBaselineDiff());
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
        diffViewer.setText("");
        collabViewer.setText("");
    }

    private void startAttack() {
        if (!requestEditor.hasMarker()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please highlight parameter value in the request editor and click 'Add Section Marker (§)' first.",
                    "Marker Required",
                    JOptionPane.WARNING_MESSAGE
            );
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
        boolean useDiff = useDiffCheck.isSelected();

        // Build Payload Queue based on checked boxes
        List<SSRFPayloadItem_littlespidy> queue = new ArrayList<>();

        for (Map.Entry<String, JCheckBox> entry : protocolCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                queue.addAll(ProtocolModules_littlespidy.getPayloads(entry.getKey()));
            }
        }

        for (Map.Entry<String, JCheckBox> entry : cloudCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                queue.addAll(CloudMetadataModules_littlespidy.getPayloads(entry.getKey()));
            }
        }

        for (Map.Entry<String, JCheckBox> entry : serviceCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                queue.addAll(ServiceExploitModules_littlespidy.getPayloads(entry.getKey()));
            }
        }

        if (queue.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No test modules selected. Please check at least one scheme/module.", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        tableModel.clear();
        clearViewers();

        startAttackBtn.setEnabled(false);
        pauseAttackBtn.setEnabled(true);
        pauseAttackBtn.setText("Pause");
        stopAttackBtn.setEnabled(true);
        progressBar.setValue(0);
        progressBar.setString("0 / " + queue.size());

        currentEngine = new SSRFScanEngine_littlespidy(
                api,
                httpService,
                requestEditor,
                tableModel,
                collaboratorManager,
                queue,
                concurrency,
                delay,
                useCollab,
                useDiff,
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
                            startAttackBtn.setEnabled(true);
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

    private static String PatternQuote(String s) {
        return java.util.regex.Pattern.quote(s);
    }
}
