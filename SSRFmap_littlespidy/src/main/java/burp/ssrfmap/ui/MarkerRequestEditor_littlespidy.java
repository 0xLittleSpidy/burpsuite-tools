// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class MarkerRequestEditor_littlespidy extends JPanel {
    private final JTextArea requestArea;
    private final JLabel markerStatusLabel;
    private static final Pattern MARKER_PATTERN = Pattern.compile("§([^§]*)§");

    public MarkerRequestEditor_littlespidy() {
        super(new BorderLayout(0, 4));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        JButton addMarkerBtn = new JButton("Add Section Marker (§)");
        addMarkerBtn.addActionListener(e -> addMarker());

        JButton clearMarkersBtn = new JButton("Clear Markers (§)");
        clearMarkersBtn.addActionListener(e -> clearMarkers());

        JButton autoDetectBtn = new JButton("Auto-Detect Marker");
        autoDetectBtn.addActionListener(e -> autoDetectMarker());

        markerStatusLabel = new JLabel("No markers defined (§...§)");

        toolbar.add(addMarkerBtn);
        toolbar.add(clearMarkersBtn);
        toolbar.add(autoDetectBtn);
        toolbar.add(markerStatusLabel);

        requestArea = new JTextArea();
        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        requestArea.setLineWrap(false);

        requestArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                updateMarkerStatus();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                updateMarkerStatus();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                updateMarkerStatus();
            }
        });

        add(toolbar, BorderLayout.NORTH);
        add(new JScrollPane(requestArea), BorderLayout.CENTER);
    }

    public void setRequestText(String text) {
        requestArea.setText(text != null ? text : "");
        updateMarkerStatus();
    }

    public String getRequestText() {
        return requestArea.getText();
    }

    public boolean hasMarker() {
        return MARKER_PATTERN.matcher(requestArea.getText()).find();
    }

    public String getMarkedParameterValue() {
        Matcher matcher = MARKER_PATTERN.matcher(requestArea.getText());
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    public String buildRequestWithPayload(String payload) {
        String currentText = requestArea.getText();
        Matcher matcher = MARKER_PATTERN.matcher(currentText);
        if (matcher.find()) {
            return currentText.substring(0, matcher.start()) + payload + currentText.substring(matcher.end());
        }
        return currentText;
    }

    public String getCleanBaselineRequest() {
        String currentText = requestArea.getText();
        Matcher matcher = MARKER_PATTERN.matcher(currentText);
        if (matcher.find()) {
            return currentText.substring(0, matcher.start()) + matcher.group(1) + currentText.substring(matcher.end());
        }
        return currentText;
    }

    public void addMarker() {
        int start = requestArea.getSelectionStart();
        int end = requestArea.getSelectionEnd();
        if (start == end) {
            return;
        }
        String text = requestArea.getText();
        String selected = text.substring(start, end);
        String replacement = "§" + selected + "§";
        requestArea.replaceRange(replacement, start, end);
        requestArea.setSelectionStart(start);
        requestArea.setSelectionEnd(start + replacement.length());
        requestArea.requestFocusInWindow();
        updateMarkerStatus();
    }

    public void clearMarkers() {
        String text = requestArea.getText();
        requestArea.setText(text.replace("§", ""));
        updateMarkerStatus();
    }

    public void autoDetectMarker() {
        String text = requestArea.getText().replace("§", "");
        Pattern pattern = Pattern.compile("(?i)(url|dest|redirect|path|uri|target|endpoint|link|webhook|callback)=([^&\\s]+)");
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            String newText = text.substring(0, matcher.start(2)) + "§" + matcher.group(2) + "§" + text.substring(matcher.end(2));
            requestArea.setText(newText);
        }
        updateMarkerStatus();
    }

    private void updateMarkerStatus() {
        String text = requestArea.getText();
        Matcher matcher = MARKER_PATTERN.matcher(text);
        int count = 0;
        String firstValue = "";
        while (matcher.find()) {
            count++;
            if (count == 1) {
                firstValue = matcher.group(1);
            }
        }

        if (count == 0) {
            markerStatusLabel.setText("No markers defined (highlight text and click 'Add Section Marker (§)')");
        } else if (count == 1) {
            markerStatusLabel.setText("1 marker defined: §" + (firstValue.length() > 30 ? firstValue.substring(0, 30) + "..." : firstValue) + "§");
        } else {
            markerStatusLabel.setText(count + " markers defined (SSRFmap targets the first active marker)");
        }
    }
}
