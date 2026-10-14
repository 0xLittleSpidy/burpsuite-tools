// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.littlespidy.gwtmap.model.GWTRpcPayload;
import com.littlespidy.gwtmap.parser.GwtLongCodec;
import com.littlespidy.gwtmap.parser.GWTRpcDeserializer;
import com.littlespidy.gwtmap.ui.GWTMapTab;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * Native Burp Suite HTTP Request Editor tab for GWT-RPC requests.
 * Displays deserialized GWT RPC calls, armed Intruder section markers (§...§),
 * and provides an embedded GWT Base64 Long converter.
 * Ports and enhances GWTab.
 *
 * @author littlespidy
 */
public class GwtMessageEditorTab implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi api;
    private final GWTMapTab mainTab;
    private final EditorCreationContext creationContext;

    private final JPanel mainPanel;
    private final JLabel headerInfoLabel;
    private final JTextArea parsedCallArea;
    private final JTextArea armedPayloadArea;
    private final JTextField b64Input;
    private final JTextField b64Output;
    private final JTextField decInput;
    private final JTextField decOutput;

    private HttpRequest currentRequest;
    private String currentArmedPayload = "";

    public GwtMessageEditorTab(MontoyaApi api, GWTMapTab mainTab, EditorCreationContext creationContext) {
        this.api = api;
        this.mainTab = mainTab;
        this.creationContext = creationContext;

        this.mainPanel = new JPanel(new BorderLayout(4, 4));
        this.mainPanel.setBorder(new EmptyBorder(4, 4, 4, 4));

        // Top Toolbar
        JPanel topBar = new JPanel(new BorderLayout(6, 4));
        headerInfoLabel = new JLabel("GWT-RPC Request: None");
        headerInfoLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));

        JPanel btnGroup = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        JButton copyArmedBtn = new JButton("Copy Armed Payload");
        copyArmedBtn.setToolTipText("Copy raw GWT payload with Intruder markers (§...§) to clipboard");
        copyArmedBtn.addActionListener(e -> {
            if (!currentArmedPayload.isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(currentArmedPayload), null);
                JOptionPane.showMessageDialog(mainPanel, "Armed GWT payload copied to clipboard.", "GWTMap", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        btnGroup.add(copyArmedBtn);

        JButton sendToDeserializerBtn = new JButton("Send to GWTMap Deserializer");
        sendToDeserializerBtn.setToolTipText("Send request body to the GWTMap suite tab for deep deserialization and fuzzing");
        sendToDeserializerBtn.addActionListener(e -> {
            if (currentRequest != null && currentRequest.bodyToString() != null) {
                if (mainTab != null) {
                    mainTab.loadPayloadIntoDeserializer(currentRequest.bodyToString());
                }
            }
        });
        btnGroup.add(sendToDeserializerBtn);

        topBar.add(headerInfoLabel, BorderLayout.CENTER);
        topBar.add(btnGroup, BorderLayout.EAST);
        mainPanel.add(topBar, BorderLayout.NORTH);

        // Sub Tabs
        JTabbedPane tabbedPane = new JTabbedPane();

        // 1. Parsed Call AST Area
        parsedCallArea = new JTextArea();
        parsedCallArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        parsedCallArea.setEditable(false);
        tabbedPane.addTab("Parsed Call", new JScrollPane(parsedCallArea));

        // 2. Armed Request Area
        armedPayloadArea = new JTextArea();
        armedPayloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        armedPayloadArea.setEditable(false);
        tabbedPane.addTab("Armed Payload (§)", new JScrollPane(armedPayloadArea));

        // 3. Base64 Long Codec Panel
        JPanel codecPanel = new JPanel();
        codecPanel.setLayout(new BoxLayout(codecPanel, BoxLayout.Y_AXIS));
        codecPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel decSection = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        decSection.setBorder(BorderFactory.createTitledBorder("GWT Base64 to Decimal Long"));
        b64Input = new JTextField(16);
        JButton decodeBtn = new JButton("Decode");
        b64Output = new JTextField(20);
        b64Output.setEditable(false);
        decodeBtn.addActionListener(e -> {
            String txt = b64Input.getText().trim();
            if (!txt.isEmpty()) {
                long val = GwtLongCodec.decode(txt);
                b64Output.setText(String.valueOf(val));
            }
        });
        decSection.add(new JLabel("Base64 Long:"));
        decSection.add(b64Input);
        decSection.add(decodeBtn);
        decSection.add(new JLabel("Decimal:"));
        decSection.add(b64Output);
        codecPanel.add(decSection);

        JPanel encSection = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        encSection.setBorder(BorderFactory.createTitledBorder("Decimal Long to GWT Base64"));
        decInput = new JTextField(16);
        JButton encodeBtn = new JButton("Encode");
        decOutput = new JTextField(20);
        decOutput.setEditable(false);
        encodeBtn.addActionListener(e -> {
            String txt = decInput.getText().trim();
            try {
                long val = Long.parseLong(txt);
                decOutput.setText(GwtLongCodec.encode(val));
            } catch (NumberFormatException ex) {
                decOutput.setText("Invalid long number");
            }
        });
        encSection.add(new JLabel("Decimal Long:"));
        encSection.add(decInput);
        encSection.add(encodeBtn);
        encSection.add(new JLabel("Base64:"));
        encSection.add(decOutput);
        codecPanel.add(encSection);

        tabbedPane.addTab("Base64 Long Codec", codecPanel);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    @Override
    public HttpRequest getRequest() {
        return currentRequest;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            currentRequest = null;
            headerInfoLabel.setText("GWT-RPC Request: None");
            parsedCallArea.setText("");
            armedPayloadArea.setText("");
            currentArmedPayload = "";
            return;
        }

        this.currentRequest = requestResponse.request();
        String body = currentRequest.bodyToString();

        if (body != null && !body.isBlank()) {
            GWTRpcPayload parsed = GWTRpcDeserializer.deserialize(body);
            String methodCall = parsed.getServiceInterface() + "." + parsed.getMethodName() + "()";
            headerInfoLabel.setText("GWT-RPC: " + methodCall + " [v" + parsed.getStreamVersion() + ", params: " + parsed.getParameters().size() + "]");

            parsedCallArea.setText(GWTRpcDeserializer.formatAstTree(parsed));
            parsedCallArea.setCaretPosition(0);

            currentArmedPayload = GWTRpcDeserializer.armWithIntruderMarkers(body);
            armedPayloadArea.setText(currentArmedPayload);
            armedPayloadArea.setCaretPosition(0);
        } else {
            headerInfoLabel.setText("GWT-RPC Request: Empty body");
            parsedCallArea.setText("");
            armedPayloadArea.setText("");
            currentArmedPayload = "";
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return false;
        }
        HttpRequest req = requestResponse.request();
        for (HttpHeader header : req.headers()) {
            String val = header.value().toLowerCase();
            if (val.contains("gwt-rpc") || val.contains("x-gwt")) {
                return true;
            }
        }
        String body = req.bodyToString();
        if (body != null && !body.isBlank()) {
            String trimmed = body.trim();
            if (trimmed.matches("^[0-9]+\\|[0-9]+\\|.*") || trimmed.contains("|0|") || trimmed.contains("|1|")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String caption() {
        return "GWT";
    }

    @Override
    public Component uiComponent() {
        return mainPanel;
    }

    @Override
    public Selection selectedData() {
        if (parsedCallArea.getSelectedText() != null && !parsedCallArea.getSelectedText().isEmpty()) {
            return Selection.selection(ByteArray.byteArray(parsedCallArea.getSelectedText()));
        }
        if (armedPayloadArea.getSelectedText() != null && !armedPayloadArea.getSelectedText().isEmpty()) {
            return Selection.selection(ByteArray.byteArray(armedPayloadArea.getSelectedText()));
        }
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }
}
