// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.uploadscanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.uploadscanner.storage.UploadPersistentStorageManager_littlespidy;
import com.littlespidy.uploadscanner.storage.UploadSessionDTO_littlespidy.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Root suite tab for Upload Scanner providing session management toolbar
 * and dynamic closeable per-request session tabs.
 * Plain ASCII text only.
 *
 * @author littlespidy
 */
public class UploadScannerTab extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane rootTabbedPane;
    private final List<UploadSessionPanel> activeSessions = new ArrayList<>();
    private UploadPersistentStorageManager_littlespidy storageManager;

    public UploadScannerTab(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;

        this.rootTabbedPane = new JTabbedPane();
        add(rootTabbedPane, BorderLayout.CENTER);
    }

    public void setStorageManager(UploadPersistentStorageManager_littlespidy storageManager) {
        this.storageManager = storageManager;
        add(storageManager.createSessionToolbar(), BorderLayout.NORTH);
        revalidate();
        repaint();
    }

    public UploadPersistentStorageManager_littlespidy getStorageManager() {
        return storageManager;
    }

    public UploadSessionPanel addNewSessionTab(HttpRequest request, HttpResponse response) {
        String path = request.path();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        if (path.length() > 22) {
            path = path.substring(0, 19) + "...";
        }
        String tabTitle = request.method() + " " + path;

        UploadSessionPanel sessionPanel = new UploadSessionPanel(
                api,
                request,
                response,
                null
        );

        activeSessions.add(sessionPanel);
        rootTabbedPane.addTab(tabTitle, sessionPanel);
        int tabIndex = rootTabbedPane.indexOfComponent(sessionPanel);

        // Custom Tab Header with Title and Close Button
        JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        tabHeader.setOpaque(false);
        JLabel titleLabel = new JLabel(tabTitle);

        JButton closeBtn = new JButton("X");
        closeBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        closeBtn.setMargin(new Insets(0, 4, 0, 4));
        closeBtn.setBorder(BorderFactory.createEmptyBorder());
        closeBtn.setContentAreaFilled(false);
        closeBtn.setFocusable(false);
        closeBtn.setToolTipText("Close this session");
        closeBtn.addActionListener(e -> closeSession(sessionPanel));

        tabHeader.add(titleLabel);
        tabHeader.add(closeBtn);
        rootTabbedPane.setTabComponentAt(tabIndex, tabHeader);

        // Switch to the newly created session tab
        rootTabbedPane.setSelectedIndex(tabIndex);

        if (storageManager != null) {
            storageManager.markDirty();
        }

        return sessionPanel;
    }

    public void restoreSessionTab(UploadTabSessionDTO dto) {
        if (dto == null) return;

        byte[] reqBytes = (dto.hasRequest && dto.requestBase64 != null)
                ? Base64.getDecoder().decode(dto.requestBase64)
                : new byte[0];
        HttpRequest request = createRequest(reqBytes, dto.requestHost, dto.requestPort, dto.requestSecure);

        HttpResponse response = (dto.hasResponse && dto.responseBase64 != null)
                ? createResponse(Base64.getDecoder().decode(dto.responseBase64))
                : null;

        String tabTitle = dto.tabTitle;
        if (tabTitle == null || tabTitle.isBlank()) {
            tabTitle = "Upload Session";
        }

        UploadSessionPanel sessionPanel = new UploadSessionPanel(
                api,
                request,
                response,
                null
        );
        sessionPanel.importDTO(dto);

        activeSessions.add(sessionPanel);
        rootTabbedPane.addTab(tabTitle, sessionPanel);
        int tabIndex = rootTabbedPane.indexOfComponent(sessionPanel);

        // Custom Tab Header with Title and Close Button
        JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        tabHeader.setOpaque(false);
        JLabel titleLabel = new JLabel(tabTitle);

        JButton closeBtn = new JButton("X");
        closeBtn.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        closeBtn.setMargin(new Insets(0, 4, 0, 4));
        closeBtn.setBorder(BorderFactory.createEmptyBorder());
        closeBtn.setContentAreaFilled(false);
        closeBtn.setFocusable(false);
        closeBtn.setToolTipText("Close this session");
        closeBtn.addActionListener(e -> closeSession(sessionPanel));

        tabHeader.add(titleLabel);
        tabHeader.add(closeBtn);
        rootTabbedPane.setTabComponentAt(tabIndex, tabHeader);

        rootTabbedPane.setSelectedIndex(tabIndex);
    }

    private ByteArray createByteArray(byte[] bytes) {
        try {
            return ByteArray.byteArray(bytes);
        } catch (Throwable t) {
            byte[] safeBytes = (bytes != null) ? bytes : new byte[0];
            return (ByteArray) java.lang.reflect.Proxy.newProxyInstance(
                    ByteArray.class.getClassLoader(),
                    new Class<?>[]{ByteArray.class},
                    (proxy, m, args) -> {
                        if ("getBytes".equals(m.getName())) return safeBytes;
                        if ("length".equals(m.getName())) return safeBytes.length;
                        return null;
                    }
            );
        }
    }

    private HttpRequest createRequest(byte[] bytes, String host, int port, boolean secure) {
        try {
            if (host != null && !host.isEmpty()) {
                HttpService service = HttpService.httpService(host, port, secure);
                return HttpRequest.httpRequest(service, createByteArray(bytes));
            } else {
                return HttpRequest.httpRequest(createByteArray(bytes));
            }
        } catch (Throwable t) {
            return (HttpRequest) java.lang.reflect.Proxy.newProxyInstance(
                    HttpRequest.class.getClassLoader(),
                    new Class<?>[]{HttpRequest.class},
                    (proxy, m, args) -> {
                        if ("method".equals(m.getName())) return "POST";
                        if ("path".equals(m.getName())) return "/";
                        if ("toByteArray".equals(m.getName())) return createByteArray(bytes);
                        if ("bodyToString".equals(m.getName())) return bytes != null ? new String(bytes) : "";
                        return null;
                    }
            );
        }
    }

    private HttpResponse createResponse(byte[] bytes) {
        try {
            return HttpResponse.httpResponse(createByteArray(bytes));
        } catch (Throwable t) {
            return (HttpResponse) java.lang.reflect.Proxy.newProxyInstance(
                    HttpResponse.class.getClassLoader(),
                    new Class<?>[]{HttpResponse.class},
                    (proxy, m, args) -> {
                        if ("statusCode".equals(m.getName())) return (short) 200;
                        if ("toByteArray".equals(m.getName())) return createByteArray(bytes);
                        return null;
                    }
            );
        }
    }

    public void closeSession(UploadSessionPanel sessionPanel) {
        int confirm = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to close this upload session?",
                "Close Session",
                JOptionPane.YES_NO_OPTION
        );
        if (confirm == JOptionPane.YES_OPTION) {
            sessionPanel.cleanup();
            activeSessions.remove(sessionPanel);
            rootTabbedPane.remove(sessionPanel);
            if (storageManager != null) {
                storageManager.markDirty();
            }
        }
    }

    public void cleanupAll() {
        for (UploadSessionPanel session : activeSessions) {
            session.cleanup();
        }
        activeSessions.clear();
    }

    public void clearAll() {
        cleanupAll();
        rootTabbedPane.removeAll();
    }

    public List<UploadSessionPanel> getActiveSessions() {
        return new ArrayList<>(activeSessions);
    }

    public SessionRootDTO exportSessionRoot() {
        SessionRootDTO root = new SessionRootDTO();
        for (UploadSessionPanel panel : activeSessions) {
            int idx = rootTabbedPane.indexOfComponent(panel);
            String title = (idx >= 0) ? rootTabbedPane.getTitleAt(idx) : "Upload Session";
            root.sessions.add(panel.exportDTO(title));
        }
        return root;
    }

    public void restoreSession(SessionRootDTO rootDto) {
        clearAll();
        if (rootDto != null && rootDto.sessions != null) {
            for (UploadTabSessionDTO s : rootDto.sessions) {
                restoreSessionTab(s);
            }
        }
    }
}
