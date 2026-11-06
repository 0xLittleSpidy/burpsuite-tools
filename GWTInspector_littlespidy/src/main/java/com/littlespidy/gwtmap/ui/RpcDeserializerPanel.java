// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.littlespidy.gwtmap.model.GWTRpcPayload;
import com.littlespidy.gwtmap.parser.GwtLongCodec;
import com.littlespidy.gwtmap.parser.GWTRpcDeserializer;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * UI panel for deserializing arbitrary GWT-RPC requests, arming them with Intruder
 * section markers (§...§), applying custom delimiters, and converting Base64 longs.
 * Ports and enhances gwtparse and GWTab.
 *
 * @author littlespidy
 */
public class RpcDeserializerPanel extends JPanel {

    private final MontoyaApi api;

    private final JTextArea inputPayloadArea = new JTextArea(5, 50);
    private final JTextArea astOutputArea = new JTextArea();
    private final JTextArea armedOutputArea = new JTextArea();

    private final JTextField b64InputField = new JTextField(16);
    private final JTextField b64OutputField = new JTextField(20);
    private final JTextField decInputField = new JTextField(16);
    private final JTextField decOutputField = new JTextField(20);

    public RpcDeserializerPanel(MontoyaApi api) {
        this.api = api;

        setLayout(new BorderLayout(6, 6));
        setBorder(new EmptyBorder(8, 8, 8, 8));

        initUI();
    }

    private void initUI() {
        // North: Input and Action Controls
        JPanel northPanel = new JPanel(new BorderLayout(6, 6));
        northPanel.setBorder(BorderFactory.createCompoundBorder(
                new TitledBorder("GWT-RPC Raw Wire Request Input"),
                new EmptyBorder(4, 6, 6, 6)
        ));

        inputPayloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        inputPayloadArea.setLineWrap(true);
        inputPayloadArea.setWrapStyleWord(true);
        JScrollPane inputScroll = new JScrollPane(inputPayloadArea);
        inputScroll.setPreferredSize(new Dimension(800, 90));
        northPanel.add(inputScroll, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        JButton deserializeBtn = new JButton("Deserialize Payload");
        deserializeBtn.addActionListener(e -> deserializePayload());
        btnPanel.add(deserializeBtn);

        JButton surroundBtn = new JButton("Surround Parameters...");
        surroundBtn.addActionListener(e -> showSurroundDialog());
        btnPanel.add(surroundBtn);

        JButton replaceBtn = new JButton("Replace Parameters...");
        replaceBtn.addActionListener(e -> showReplaceDialog());
        btnPanel.add(replaceBtn);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            inputPayloadArea.setText("");
            astOutputArea.setText("");
            armedOutputArea.setText("");
        });
        btnPanel.add(clearBtn);

        northPanel.add(btnPanel, BorderLayout.SOUTH);
        add(northPanel, BorderLayout.NORTH);

        // Center: Split Pane for Deserialized Tree and Armed Output
        JPanel leftPanel = new JPanel(new BorderLayout(4, 4));
        leftPanel.setBorder(BorderFactory.createTitledBorder("Deserialized Method Call (AST & Type Hierarchy)"));
        astOutputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        astOutputArea.setEditable(false);
        leftPanel.add(new JScrollPane(astOutputArea), BorderLayout.CENTER);

        JPanel rightPanel = new JPanel(new BorderLayout(4, 4));
        rightPanel.setBorder(BorderFactory.createTitledBorder("Armed / Mutated Wire Payload"));
        armedOutputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        armedOutputArea.setLineWrap(true);
        armedOutputArea.setWrapStyleWord(true);
        rightPanel.add(new JScrollPane(armedOutputArea), BorderLayout.CENTER);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        centerSplit.setResizeWeight(0.5);
        add(centerSplit, BorderLayout.CENTER);

        // South: Base64 Long Codec
        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        southPanel.setBorder(BorderFactory.createCompoundBorder(
                new TitledBorder("GWT Base64 Long Codec (RFC 4648 / GWT Alphabet)"),
                new EmptyBorder(4, 6, 4, 6)
        ));

        // Decode: Base64 -> Decimal
        southPanel.add(new JLabel("Base64 Long:"));
        southPanel.add(b64InputField);
        JButton decodeBtn = new JButton("Decode to Decimal");
        decodeBtn.addActionListener(e -> {
            String txt = b64InputField.getText().trim();
            if (!txt.isEmpty()) {
                long val = GwtLongCodec.decode(txt);
                b64OutputField.setText(String.valueOf(val));
            }
        });
        southPanel.add(decodeBtn);
        southPanel.add(new JLabel("Decimal:"));
        b64OutputField.setEditable(false);
        southPanel.add(b64OutputField);

        southPanel.add(new JSeparator(SwingConstants.VERTICAL));

        // Encode: Decimal -> Base64
        southPanel.add(new JLabel("Decimal Long:"));
        southPanel.add(decInputField);
        JButton encodeBtn = new JButton("Encode to Base64");
        encodeBtn.addActionListener(e -> {
            String txt = decInputField.getText().trim();
            try {
                long val = Long.parseLong(txt);
                decOutputField.setText(GwtLongCodec.encode(val));
            } catch (NumberFormatException ex) {
                decOutputField.setText("Invalid number");
            }
        });
        southPanel.add(encodeBtn);
        southPanel.add(new JLabel("Base64:"));
        decOutputField.setEditable(false);
        southPanel.add(decOutputField);

        add(southPanel, BorderLayout.SOUTH);
    }

    /**
     * Sets the raw payload into the text area and automatically triggers deserialization.
     */
    public void setPayload(String payload) {
        if (payload != null) {
            inputPayloadArea.setText(payload.trim());
            deserializePayload();
        }
    }

    public void setTargetUrl(String url) {
        // Kept for backward compatibility
    }

    private void deserializePayload() {
        String raw = inputPayloadArea.getText().trim();
        if (raw.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a GWT-RPC payload to deserialize.", "GWTMap", JOptionPane.WARNING_MESSAGE);
            return;
        }

        GWTRpcPayload parsed = GWTRpcDeserializer.deserialize(raw);
        astOutputArea.setText(GWTRpcDeserializer.formatAstTree(parsed));
        astOutputArea.setCaretPosition(0);

        String armed = GWTRpcDeserializer.armWithIntruderMarkers(raw);
        armedOutputArea.setText(armed);
        armedOutputArea.setCaretPosition(0);
    }

    private void armPayload(String prefix, String suffix) {
        String raw = inputPayloadArea.getText().trim();
        if (raw.isEmpty()) return;

        String armed = GWTRpcDeserializer.surroundFuzzable(raw, prefix, suffix);
        armedOutputArea.setText(armed);
        armedOutputArea.setCaretPosition(0);
    }

    private void showSurroundDialog() {
        String raw = inputPayloadArea.getText().trim();
        if (raw.isEmpty()) return;

        JTextField prefixField = new JTextField("[[", 8);
        JTextField suffixField = new JTextField("]]", 8);

        JPanel panel = new JPanel(new GridLayout(2, 2, 6, 6));
        panel.add(new JLabel("Prefix:"));
        panel.add(prefixField);
        panel.add(new JLabel("Suffix:"));
        panel.add(suffixField);

        int result = JOptionPane.showConfirmDialog(this, panel, "Surround Fuzzable Parameters", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            armPayload(prefixField.getText(), suffixField.getText());
        }
    }

    private void showReplaceDialog() {
        String raw = inputPayloadArea.getText().trim();
        if (raw.isEmpty()) return;

        String replacement = JOptionPane.showInputDialog(this, "Enter replacement string for all fuzzable parameters:", "%s");
        if (replacement != null && !replacement.isEmpty()) {
            String mutated = GWTRpcDeserializer.replaceFuzzable(raw, replacement);
            armedOutputArea.setText(mutated);
            armedOutputArea.setCaretPosition(0);
        }
    }
}
