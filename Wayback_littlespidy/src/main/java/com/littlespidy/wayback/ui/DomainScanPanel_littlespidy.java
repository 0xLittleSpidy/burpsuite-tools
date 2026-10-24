// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.wayback.ui;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.wayback.config.CommonConfig_littlespidy;
import com.littlespidy.wayback.model.DirectoryFinding_littlespidy;
import com.littlespidy.wayback.model.DiscoveredPath_littlespidy;
import com.littlespidy.wayback.model.DiscoveredSubdomain_littlespidy;
import com.littlespidy.wayback.model.DomainScanConfig_littlespidy;
import com.littlespidy.wayback.service.DirectoryListingScanner_littlespidy;
import com.littlespidy.wayback.service.WaybackCdxClient_littlespidy;
import com.littlespidy.wayback.service.WaybackUrlParser_littlespidy;
import com.littlespidy.wayback.session.SessionData_littlespidy.DomainSessionState_littlespidy;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public class DomainScanPanel_littlespidy extends JPanel {

    private final MontoyaApi api;
    private final CommonConfig_littlespidy commonConfig;
    private final DomainScanConfig_littlespidy scanConfig;
    private final Runnable onStateChanged;

    private final JTextField domainField;
    private final JCheckBox autoSubdomainsChk;
    private final JCheckBox inScopeOnlyChk;
    private final JCheckBox addToSiteMapChk;
    private final JSpinner threadsSpinner;
    private final JSpinner delaySpinner;
    private final JSpinner timeoutSpinner;

    private final JButton startBtn = new JButton("Start Scan");
    private final JButton pauseBtn = new JButton("Pause");
    private final JButton stopBtn = new JButton("Stop");
    private final JButton clearBtn = new JButton("Clear");
    private final JButton exportBtn = new JButton("Export CSV");

    private final JLabel kpiHarvested = new JLabel("0");
    private final JLabel kpiUniquePaths = new JLabel("0");
    private final JLabel kpiSubdomains = new JLabel("0");
    private final JLabel kpiProbed = new JLabel("0 / 0");
    private final JLabel kpiFindings = new JLabel("0");

    private final JProgressBar progressBar = new JProgressBar(0, 100);
    private final JTabbedPane childTabbedPane = new JTabbedPane();

    private final PathsTab_littlespidy pathsTab;
    private final SubdomainsTab_littlespidy subdomainsTab;
    private final DirectoryListingTab_littlespidy directoryListingTab;

    private DirectoryListingScanner_littlespidy scanner;
    private Consumer<String> openDomainInNewTabConsumer;

    public DomainScanPanel_littlespidy(
            MontoyaApi api,
            CommonConfig_littlespidy commonConfig,
            String initialDomain,
            Runnable onStateChanged) {
        super(new BorderLayout(6, 6));
        this.api = api;
        this.commonConfig = commonConfig;
        this.scanConfig = new DomainScanConfig_littlespidy(initialDomain);
        this.onStateChanged = onStateChanged;

        this.domainField = new JTextField(initialDomain, 18);
        this.autoSubdomainsChk = new JCheckBox("Auto-discover Subdomains (*.domain/*)", scanConfig.isAutoDiscoverSubdomains());
        this.inScopeOnlyChk = new JCheckBox("In-Scope Only", scanConfig.isInScopeOnly());
        this.addToSiteMapChk = new JCheckBox("Add to Burp Site Map", scanConfig.isAddToSiteMap());
        this.threadsSpinner = new JSpinner(new SpinnerNumberModel(scanConfig.getThreads(), 1, 50, 1));
        this.delaySpinner = new JSpinner(new SpinnerNumberModel(scanConfig.getDelayMs(), 0, 5000, 25));
        this.timeoutSpinner = new JSpinner(new SpinnerNumberModel(scanConfig.getTimeoutSec(), 2, 60, 1));

        this.pathsTab = new PathsTab_littlespidy(api);
        this.subdomainsTab = new SubdomainsTab_littlespidy(api);
        this.directoryListingTab = new DirectoryListingTab_littlespidy(api);

        initUI();
    }

    private void initUI() {
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        // Top Control Panel
        JPanel topPanel = new JPanel(new BorderLayout(4, 4));

        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new BoxLayout(controlPanel, BoxLayout.Y_AXIS));
        controlPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)
        ));

        // Row 1: Target domain, Checkboxes, Action Buttons
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        row1.add(new JLabel("Target Domain:"));
        row1.add(domainField);
        row1.add(autoSubdomainsChk);
        row1.add(inScopeOnlyChk);
        row1.add(addToSiteMapChk);

        startBtn.setFont(startBtn.getFont().deriveFont(Font.BOLD));
        startBtn.addActionListener(e -> startScan());
        pauseBtn.setEnabled(false);
        pauseBtn.addActionListener(e -> togglePause());
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopScan());
        clearBtn.addActionListener(e -> clearData());
        exportBtn.addActionListener(e -> exportFindingsCsv());

        row1.add(startBtn);
        row1.add(pauseBtn);
        row1.add(stopBtn);
        row1.add(clearBtn);
        row1.add(exportBtn);
        controlPanel.add(row1);

        // Row 2: Concurrency, Delay, Timeout, Metric KPI Cards
        JPanel row2 = new JPanel(new BorderLayout(8, 2));

        JPanel perfPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        perfPanel.add(new JLabel("Threads:"));
        perfPanel.add(threadsSpinner);
        perfPanel.add(new JLabel("Delay (ms):"));
        perfPanel.add(delaySpinner);
        perfPanel.add(new JLabel("Timeout (s):"));
        perfPanel.add(timeoutSpinner);

        JPanel kpiPanel = new JPanel(new GridLayout(1, 5, 6, 0));
        kpiPanel.add(createKpiCard("CDX Harvested", kpiHarvested, false));
        kpiPanel.add(createKpiCard("Unique Paths", kpiUniquePaths, false));
        kpiPanel.add(createKpiCard("Subdomains", kpiSubdomains, false));
        kpiPanel.add(createKpiCard("Probed", kpiProbed, false));
        kpiPanel.add(createKpiCard("Open Listings", kpiFindings, true));

        row2.add(perfPanel, BorderLayout.WEST);
        row2.add(kpiPanel, BorderLayout.EAST);
        controlPanel.add(row2);

        // Row 3: Progress Bar
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        controlPanel.add(Box.createVerticalStrut(4));
        controlPanel.add(progressBar);

        topPanel.add(controlPanel, BorderLayout.CENTER);
        add(topPanel, BorderLayout.NORTH);

        // Child Tabs (Strict order: 1. Path, 2. Subdomain, 3. Directory Listing)
        childTabbedPane.addTab("Path", pathsTab);
        childTabbedPane.addTab("Subdomain", subdomainsTab);
        childTabbedPane.addTab("Directory Listing", directoryListingTab);

        add(childTabbedPane, BorderLayout.CENTER);

        // Wire subdomains tab to open dedicated tab callback
        subdomainsTab.setScanInNewTabCallback(sub -> {
            if (openDomainInNewTabConsumer != null) {
                openDomainInNewTabConsumer.accept(sub);
            }
        });

        // Wire re-test path
        pathsTab.setRetestCallback(pathItem -> {
            if (scanner != null && scanner.isRunning()) {
                JOptionPane.showMessageDialog(this, "Scan already in progress. Please pause or stop the current scan before re-testing single paths.", "Scan Active", JOptionPane.WARNING_MESSAGE);
                return;
            }
            List<DiscoveredPath_littlespidy> single = List.of(pathItem);
            runScannerOnPaths(single);
        });
    }

    private JPanel createKpiCard(String title, JLabel valueLabel, boolean highlight) {
        JPanel card = new JPanel(new BorderLayout(2, 2));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color.LIGHT_GRAY, 1),
                BorderFactory.createEmptyBorder(2, 6, 2, 6)
        ));
        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(titleLbl.getFont().deriveFont(9f));
        titleLbl.setForeground(Color.GRAY);
        card.add(titleLbl, BorderLayout.NORTH);

        valueLabel.setFont(valueLabel.getFont().deriveFont(Font.BOLD, 13f));
        if (highlight) {
            valueLabel.setForeground(new Color(229, 107, 31)); // Burp orange
        }
        card.add(valueLabel, BorderLayout.CENTER);
        return card;
    }

    public void setOpenDomainInNewTabConsumer(Consumer<String> consumer) {
        this.openDomainInNewTabConsumer = consumer;
    }

    public String getTargetDomain() {
        return domainField.getText().trim();
    }

    public void setTargetDomain(String domain) {
        if (domain != null) {
            domainField.setText(domain.trim());
            scanConfig.setTargetDomain(domain.trim());
        }
    }

    public void startScan() {
        String domain = getTargetDomain();
        if (domain.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a valid target domain.", "Missing Target", JOptionPane.WARNING_MESSAGE);
            return;
        }

        scanConfig.setTargetDomain(domain);
        scanConfig.setAutoDiscoverSubdomains(autoSubdomainsChk.isSelected());
        scanConfig.setInScopeOnly(inScopeOnlyChk.isSelected());
        scanConfig.setAddToSiteMap(addToSiteMapChk.isSelected());
        scanConfig.setThreads((Integer) threadsSpinner.getValue());
        scanConfig.setDelayMs((Integer) delaySpinner.getValue());
        scanConfig.setTimeoutSec((Integer) timeoutSpinner.getValue());

        startBtn.setEnabled(false);
        pauseBtn.setEnabled(true);
        pauseBtn.setText("Pause");
        stopBtn.setEnabled(true);

        progressBar.setIndeterminate(true);
        progressBar.setString("Querying Wayback CDX API for " + domain + "...");

        Thread worker = new Thread(() -> {
            WaybackCdxClient_littlespidy cdxClient = new WaybackCdxClient_littlespidy(api, commonConfig);
            List<String> rawUrls = cdxClient.fetchWaybackUrls(domain, scanConfig.isAutoDiscoverSubdomains(), msg -> {
                SwingUtilities.invokeLater(() -> progressBar.setString(msg));
            });

            SwingUtilities.invokeLater(() -> {
                kpiHarvested.setText(String.format("%,d", rawUrls.size()));
            });

            if (rawUrls.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setIndeterminate(false);
                    progressBar.setValue(0);
                    progressBar.setString("No Wayback records found for " + domain);
                    startBtn.setEnabled(true);
                    pauseBtn.setEnabled(false);
                    stopBtn.setEnabled(false);
                });
                return;
            }

            // Extract subdomains
            List<String> subdomains = WaybackUrlParser_littlespidy.extractSubdomains(rawUrls, domain);
            Map<String, Set<String>> domainPathsMap = WaybackUrlParser_littlespidy.extractDomainPathsMap(rawUrls, domain);

            List<DiscoveredSubdomain_littlespidy> subList = new ArrayList<>();
            for (String sub : subdomains) {
                int pathsCount = domainPathsMap.containsKey(sub) ? domainPathsMap.get(sub).size() : 0;
                subList.add(new DiscoveredSubdomain_littlespidy(sub, pathsCount));
            }

            // Extract paths for this target
            List<String> rawPaths = WaybackUrlParser_littlespidy.extractPathsForDomain(rawUrls, domain);
            List<DiscoveredPath_littlespidy> pathObjects = new ArrayList<>();
            for (String p : rawPaths) {
                pathObjects.add(new DiscoveredPath_littlespidy(domain, p));
            }

            SwingUtilities.invokeLater(() -> {
                kpiUniquePaths.setText(String.format("%,d", pathObjects.size()));
                kpiSubdomains.setText(String.format("%,d", subList.size()));
                subdomainsTab.setSubdomains(subList);
                pathsTab.setPaths(pathObjects);
                progressBar.setIndeterminate(false);
            });

            runScannerOnPaths(pathObjects);
        }, "Wayback-Harvest-Worker-" + domain);
        worker.setDaemon(true);
        worker.start();

        if (onStateChanged != null) onStateChanged.run();
    }

    private void runScannerOnPaths(List<DiscoveredPath_littlespidy> pathObjects) {
        if (pathObjects == null || pathObjects.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                progressBar.setString("No paths to scan.");
                startBtn.setEnabled(true);
                pauseBtn.setEnabled(false);
                stopBtn.setEnabled(false);
            });
            return;
        }

        scanner = new DirectoryListingScanner_littlespidy(api, commonConfig, scanConfig);
        int total = pathObjects.size();

        SwingUtilities.invokeLater(() -> {
            progressBar.setMaximum(total);
            progressBar.setValue(0);
            progressBar.setString("Probing 0 of " + total + " paths...");
        });

        scanner.startScan(pathObjects, new DirectoryListingScanner_littlespidy.ScanProgressCallback() {
            @Override
            public void onProgress(int completed, int totalCount, String currentPath) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(completed);
                    int pct = totalCount > 0 ? (completed * 100 / totalCount) : 0;
                    progressBar.setString("Probing " + completed + " of " + totalCount + " (" + pct + "%) - " + currentPath);
                    kpiProbed.setText(completed + " / " + totalCount);
                });
            }

            @Override
            public void onFindingDiscovered(DirectoryFinding_littlespidy finding) {
                SwingUtilities.invokeLater(() -> {
                    directoryListingTab.addFinding(finding);
                    kpiFindings.setText(String.valueOf(directoryListingTab.getFindings().size()));
                    if (onStateChanged != null) onStateChanged.run();
                });
            }

            @Override
            public void onPathUpdated(DiscoveredPath_littlespidy path) {
                SwingUtilities.invokeLater(() -> pathsTab.updatePath(path));
            }

            @Override
            public void onScanCompleted() {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(total);
                    progressBar.setString("Scan completed. " + directoryListingTab.getFindings().size() + " open directories identified.");
                    startBtn.setEnabled(true);
                    pauseBtn.setEnabled(false);
                    stopBtn.setEnabled(false);
                    if (onStateChanged != null) onStateChanged.run();
                });
            }
        });
    }

    private void togglePause() {
        if (scanner == null) return;
        if (scanner.isPaused()) {
            scanner.resumeScan();
            pauseBtn.setText("Pause");
            progressBar.setString("Scan resumed.");
        } else {
            scanner.pauseScan();
            pauseBtn.setText("Resume");
            progressBar.setString("Scan paused.");
        }
    }

    public void stopScan() {
        if (scanner != null) {
            scanner.stopScan();
        }
        startBtn.setEnabled(true);
        pauseBtn.setEnabled(false);
        stopBtn.setEnabled(false);
        progressBar.setString("Scan stopped.");
        if (onStateChanged != null) onStateChanged.run();
    }

    public void clearData() {
        if (scanner != null && scanner.isRunning()) {
            int res = JOptionPane.showConfirmDialog(this, "A scan is currently active. Stop and clear data?", "Confirm Clear", JOptionPane.YES_NO_OPTION);
            if (res != JOptionPane.YES_OPTION) return;
            scanner.stopScan();
        }
        pathsTab.clear();
        subdomainsTab.clear();
        directoryListingTab.clear();
        kpiHarvested.setText("0");
        kpiUniquePaths.setText("0");
        kpiSubdomains.setText("0");
        kpiProbed.setText("0 / 0");
        kpiFindings.setText("0");
        progressBar.setValue(0);
        progressBar.setString("Ready");
        startBtn.setEnabled(true);
        pauseBtn.setEnabled(false);
        stopBtn.setEnabled(false);
        if (onStateChanged != null) onStateChanged.run();
    }

    private void exportFindingsCsv() {
        List<DirectoryFinding_littlespidy> findings = directoryListingTab.getFindings();
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No directory listings to export.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("wayback_findings_" + getTargetDomain() + ".csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter writer = new PrintWriter(chooser.getSelectedFile())) {
                writer.println("ID,Protocol,Host,Path,FullURL,Status,MatchedSignature,ContentLength,Timestamp");
                for (DirectoryFinding_littlespidy f : findings) {
                    writer.printf("%d,%s,%s,%s,%s,%d,\"%s\",%d,%s%n",
                            f.getId(), f.getProtocol(), f.getHost(), f.getPath(), f.getFullUrl(),
                            f.getStatusCode(), f.getMatchedSignature().replace("\"", "\"\""),
                            f.getContentLength(), f.getTimestamp());
                }
                JOptionPane.showMessageDialog(this, "Exported " + findings.size() + " findings successfully.", "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error exporting CSV: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public DomainSessionState_littlespidy exportState() {
        DomainSessionState_littlespidy state = new DomainSessionState_littlespidy();
        state.domain = getTargetDomain();
        state.scanConfig = scanConfig;
        state.paths = pathsTab.getPaths();
        state.subdomains = subdomainsTab.getSubdomains();
        state.findings = directoryListingTab.getFindings();
        return state;
    }

    public void importState(DomainSessionState_littlespidy state) {
        if (state == null) return;
        setTargetDomain(state.domain);
        if (state.scanConfig != null) {
            autoSubdomainsChk.setSelected(state.scanConfig.isAutoDiscoverSubdomains());
            inScopeOnlyChk.setSelected(state.scanConfig.isInScopeOnly());
            addToSiteMapChk.setSelected(state.scanConfig.isAddToSiteMap());
            threadsSpinner.setValue(state.scanConfig.getThreads());
            delaySpinner.setValue(state.scanConfig.getDelayMs());
            timeoutSpinner.setValue(state.scanConfig.getTimeoutSec());
        }
        pathsTab.setPaths(state.paths);
        subdomainsTab.setSubdomains(state.subdomains);
        directoryListingTab.setFindings(state.findings);

        kpiUniquePaths.setText(String.valueOf(state.paths != null ? state.paths.size() : 0));
        kpiSubdomains.setText(String.valueOf(state.subdomains != null ? state.subdomains.size() : 0));
        kpiFindings.setText(String.valueOf(state.findings != null ? state.findings.size() : 0));
        kpiProbed.setText((state.paths != null ? state.paths.size() : 0) + " / " + (state.paths != null ? state.paths.size() : 0));
        progressBar.setValue(100);
        progressBar.setString("Loaded from session.");
    }
}
