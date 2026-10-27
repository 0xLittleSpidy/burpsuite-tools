// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.quickhelper.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.littlespidy.quickhelper.model.AuthItem_littlespidy;
import com.littlespidy.quickhelper.service.AuthTokenExtractorService_littlespidy;
import com.littlespidy.quickhelper.service.ClipboardService_littlespidy;
import com.littlespidy.quickhelper.ui.AuthItemTableModel_littlespidy;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Custom Request Editor tab providing one-click copying for session cookies,
 * authorization headers, Bearer tokens, and custom API tokens.
 */
public class AuthRequestEditorTab_littlespidy implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi api;
    private final EditorCreationContext creationContext;
    private final ClipboardService_littlespidy clipboardService;
    private final AuthTokenExtractorService_littlespidy extractorService;

    private final JPanel mainPanel;
    private final JButton btnCopyBearer;
    private final JButton btnCopyAuthHeader;
    private final JButton btnCopyCookieHeader;
    private final JButton btnCopyAllCookies;
    private final JLabel statusLabel;

    private final AuthItemTableModel_littlespidy tableModel;
    private final JTable authTable;
    private final JTextArea detailTextArea;
    private final JLabel detailTitleLabel;

    private HttpRequest originalRequest;
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    public AuthRequestEditorTab_littlespidy(MontoyaApi api,
                                           EditorCreationContext creationContext,
                                           ClipboardService_littlespidy clipboardService,
                                           AuthTokenExtractorService_littlespidy extractorService) {
        this.api = api;
        this.creationContext = creationContext;
        this.clipboardService = clipboardService;
        this.extractorService = extractorService;

        this.mainPanel = new JPanel(new BorderLayout(0, 6));
        this.mainPanel.setBorder(new EmptyBorder(6, 6, 6, 6));

        // Top Control Area: Quick Action Buttons & Status Strip
        JPanel topContainer = new JPanel(new BorderLayout(0, 4));

        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JLabel actionLabel = new JLabel("Quick Copy:");
        actionLabel.setFont(actionLabel.getFont().deriveFont(Font.BOLD));
        buttonBar.add(actionLabel);

        btnCopyBearer = new JButton("Copy Bearer Token");
        btnCopyAuthHeader = new JButton("Copy Auth Header");
        btnCopyCookieHeader = new JButton("Copy Cookie Header");
        btnCopyAllCookies = new JButton("Copy All Cookies");

        btnCopyBearer.setEnabled(false);
        btnCopyAuthHeader.setEnabled(false);
        btnCopyCookieHeader.setEnabled(false);
        btnCopyAllCookies.setEnabled(false);

        buttonBar.add(btnCopyBearer);
        buttonBar.add(btnCopyAuthHeader);
        buttonBar.add(btnCopyCookieHeader);
        buttonBar.add(btnCopyAllCookies);

        // Status Strip
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                new EmptyBorder(4, 8, 4, 8)
        ));
        statusLabel = new JLabel("Ready");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        statusPanel.add(statusLabel, BorderLayout.CENTER);

        topContainer.add(buttonBar, BorderLayout.NORTH);
        topContainer.add(statusPanel, BorderLayout.SOUTH);
        mainPanel.add(topContainer, BorderLayout.NORTH);

        // Center Table
        tableModel = new AuthItemTableModel_littlespidy();
        authTable = new JTable(tableModel);
        authTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        authTable.setFillsViewportHeight(true);
        authTable.setAutoCreateRowSorter(true);

        // Column widths
        if (authTable.getColumnModel().getColumnCount() >= 4) {
            authTable.getColumnModel().getColumn(0).setPreferredWidth(120);
            authTable.getColumnModel().getColumn(1).setPreferredWidth(150);
            authTable.getColumnModel().getColumn(2).setPreferredWidth(90);
            authTable.getColumnModel().getColumn(3).setPreferredWidth(400);
        }

        JScrollPane tableScroll = new JScrollPane(authTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Extracted Tokens and Cookies"));

        // Bottom Detail View
        JPanel detailPanel = new JPanel(new BorderLayout(0, 4));
        detailPanel.setBorder(BorderFactory.createTitledBorder("Selected Item Details"));

        JPanel detailHeader = new JPanel(new BorderLayout());
        detailTitleLabel = new JLabel("Selected Item: (None)");
        detailTitleLabel.setFont(detailTitleLabel.getFont().deriveFont(Font.BOLD, 11f));

        JButton btnCopySelected = new JButton("Copy Selected Value");
        btnCopySelected.addActionListener(e -> copySelectedValue());

        detailHeader.add(detailTitleLabel, BorderLayout.CENTER);
        detailHeader.add(btnCopySelected, BorderLayout.EAST);

        detailTextArea = new JTextArea();
        detailTextArea.setEditable(false);
        detailTextArea.setLineWrap(true);
        detailTextArea.setWrapStyleWord(true);
        detailTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailTextArea);
        detailScroll.setPreferredSize(new Dimension(200, 90));

        detailPanel.add(detailHeader, BorderLayout.NORTH);
        detailPanel.add(detailScroll, BorderLayout.CENTER);

        // Split pane between Table and Detail view
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailPanel);
        splitPane.setResizeWeight(0.65);
        splitPane.setContinuousLayout(true);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        // Event Listeners
        initListeners();
    }

    private void initListeners() {
        // Quick Action Button Listeners
        btnCopyBearer.addActionListener(e -> {
            String bearer = extractorService.extractBearerToken(originalRequest);
            if (bearer != null && !bearer.isEmpty()) {
                clipboardService.copyToClipboard(bearer);
                updateStatus("Copied Bearer Token to clipboard (" + bearer.length() + " chars)");
            }
        });

        btnCopyAuthHeader.addActionListener(e -> {
            String auth = extractorService.extractAuthHeader(originalRequest);
            if (auth != null && !auth.isEmpty()) {
                clipboardService.copyToClipboard(auth);
                updateStatus("Copied Authorization Header to clipboard (" + auth.length() + " chars)");
            }
        });

        btnCopyCookieHeader.addActionListener(e -> {
            String cookie = extractorService.extractCookieHeader(originalRequest);
            if (cookie != null && !cookie.isEmpty()) {
                clipboardService.copyToClipboard(cookie);
                updateStatus("Copied Complete Cookie Header to clipboard (" + cookie.length() + " chars)");
            }
        });

        btnCopyAllCookies.addActionListener(e -> {
            String cookie = extractorService.extractCookieHeader(originalRequest);
            if (cookie != null && !cookie.isEmpty()) {
                clipboardService.copyToClipboard(cookie);
                updateStatus("Copied All Cookies to clipboard (" + cookie.length() + " chars)");
            }
        });

        // Table Selection Listener
        authTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = authTable.getSelectedRow();
                if (selectedRow >= 0) {
                    int modelRow = authTable.convertRowIndexToModel(selectedRow);
                    AuthItem_littlespidy item = tableModel.getItem(modelRow);
                    if (item != null) {
                        detailTitleLabel.setText("Selected Item: " + item.getName() + " (" + item.getType() + ")");
                        detailTextArea.setText(item.getValue());
                        detailTextArea.setCaretPosition(0);
                    }
                }
            }
        });

        // Table Double-Click and Right-Click Context Menu
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyValueItem = new JMenuItem("Copy Value");
        copyValueItem.addActionListener(e -> copySelectedValue());
        popupMenu.add(copyValueItem);

        JMenuItem copyNameAndValueItem = new JMenuItem("Copy Name=Value");
        copyNameAndValueItem.addActionListener(e -> copySelectedNameAndValue());
        popupMenu.add(copyNameAndValueItem);

        authTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    copySelectedValue();
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = authTable.rowAtPoint(e.getPoint());
                    if (row >= 0 && !authTable.isRowSelected(row)) {
                        authTable.setRowSelectionInterval(row, row);
                    }
                    if (authTable.getSelectedRow() >= 0) {
                        popupMenu.show(authTable, e.getX(), e.getY());
                    }
                }
            }
        });
    }

    private void copySelectedValue() {
        int selectedRow = authTable.getSelectedRow();
        if (selectedRow >= 0) {
            int modelRow = authTable.convertRowIndexToModel(selectedRow);
            AuthItem_littlespidy item = tableModel.getItem(modelRow);
            if (item != null && item.getValue() != null) {
                clipboardService.copyToClipboard(item.getValue());
                updateStatus("Copied " + item.getName() + " to clipboard (" + item.getLength() + " chars)");
            }
        }
    }

    private void copySelectedNameAndValue() {
        int selectedRow = authTable.getSelectedRow();
        if (selectedRow >= 0) {
            int modelRow = authTable.convertRowIndexToModel(selectedRow);
            AuthItem_littlespidy item = tableModel.getItem(modelRow);
            if (item != null) {
                String text = item.getName() + "=" + item.getValue();
                clipboardService.copyToClipboard(text);
                updateStatus("Copied " + item.getName() + "=value to clipboard");
            }
        }
    }

    private void updateStatus(String message) {
        String timestamp = timeFormat.format(new Date());
        statusLabel.setText("[OK] " + message + " at " + timestamp);
    }

    @Override
    public HttpRequest getRequest() {
        return originalRequest;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            this.originalRequest = null;
            Runnable clearUi = () -> {
                tableModel.clear();
                btnCopyBearer.setEnabled(false);
                btnCopyAuthHeader.setEnabled(false);
                btnCopyCookieHeader.setEnabled(false);
                btnCopyAllCookies.setEnabled(false);
                detailTitleLabel.setText("Selected Item: (None)");
                detailTextArea.setText("");
                statusLabel.setText("No request loaded");
            };
            if (SwingUtilities.isEventDispatchThread()) {
                clearUi.run();
            } else {
                SwingUtilities.invokeLater(clearUi);
            }
            return;
        }

        this.originalRequest = requestResponse.request();
        List<AuthItem_littlespidy> items = extractorService.extractAll(this.originalRequest);

        String bearer = extractorService.extractBearerToken(this.originalRequest);
        String authHeader = extractorService.extractAuthHeader(this.originalRequest);
        String cookieHeader = extractorService.extractCookieHeader(this.originalRequest);

        Runnable updateUi = () -> {
            tableModel.setItems(items);
            btnCopyBearer.setEnabled(bearer != null && !bearer.isEmpty());
            btnCopyAuthHeader.setEnabled(authHeader != null && !authHeader.isEmpty());
            btnCopyCookieHeader.setEnabled(cookieHeader != null && !cookieHeader.isEmpty());
            btnCopyAllCookies.setEnabled(cookieHeader != null && !cookieHeader.isEmpty());

            if (items.isEmpty()) {
                detailTitleLabel.setText("Selected Item: (None)");
                detailTextArea.setText("");
                statusLabel.setText("No authorization headers or cookies detected in this request");
            } else {
                statusLabel.setText("Ready - " + items.size() + " session token(s) and cookie(s) detected");
                if (authTable.getRowCount() > 0) {
                    authTable.setRowSelectionInterval(0, 0);
                }
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            updateUi.run();
        } else {
            SwingUtilities.invokeLater(updateUi);
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        return requestResponse != null && requestResponse.request() != null;
    }

    @Override
    public String caption() {
        return "Copy";
    }

    @Override
    public Component uiComponent() {
        return mainPanel;
    }

    @Override
    public Selection selectedData() {
        if (detailTextArea.getSelectedText() != null) {
            return Selection.selection(detailTextArea.getSelectionStart(), detailTextArea.getSelectionEnd());
        }
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }
}
