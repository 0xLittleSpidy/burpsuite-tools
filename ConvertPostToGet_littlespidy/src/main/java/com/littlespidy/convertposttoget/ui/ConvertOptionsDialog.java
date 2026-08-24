package com.littlespidy.convertposttoget.ui;

import com.littlespidy.convertposttoget.model.ConvertPostToGetConfig;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Created with the help of an AI Agent and littlespidy.
 *
 * Options dialog for configuring threads, delays, and header stripping rules.
 *
 * @author littlespidy
 */
public class ConvertOptionsDialog extends JDialog {
    public ConvertOptionsDialog(Frame owner, ConvertPostToGetConfig config) {
        super(owner, "Convert POST to GET Options", true);

        setLayout(new BorderLayout(10, 10));
        setSize(520, 320);
        setLocationRelativeTo(owner);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel perfGroup = new JPanel(new GridLayout(0, 2, 8, 8));
        perfGroup.setBorder(new TitledBorder("Execution Pacing & Concurrency"));

        JSpinner threadsSpinner = new JSpinner(new SpinnerNumberModel(config.getMaxConcurrentThreads(), 1, 50, 1));
        JSpinner delaySpinner = new JSpinner(new SpinnerNumberModel(config.getDelayBetweenRequestsMs(), 0, 10000, 50));
        JCheckBox stripContentTypeCb = new JCheckBox("Strip Content-Type & Content-Length on GET", config.isUpdateContentTypeHeaders());

        perfGroup.add(new JLabel("Max Concurrent Threads:"));
        perfGroup.add(threadsSpinner);
        perfGroup.add(new JLabel("Delay Between Requests (ms):"));
        perfGroup.add(delaySpinner);

        mainPanel.add(perfGroup);
        mainPanel.add(Box.createVerticalStrut(10));

        JPanel headerGroup = new JPanel(new GridLayout(0, 1, 6, 6));
        headerGroup.setBorder(new TitledBorder("Header Rules"));
        headerGroup.add(stripContentTypeCb);
        mainPanel.add(headerGroup);

        add(mainPanel, BorderLayout.CENTER);

        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveBtn = new JButton("Save");
        saveBtn.addActionListener(e -> {
            config.setMaxConcurrentThreads((Integer) threadsSpinner.getValue());
            config.setDelayBetweenRequestsMs((Integer) delaySpinner.getValue());
            config.setUpdateContentTypeHeaders(stripContentTypeCb.isSelected());
            dispose();
        });

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        actionPanel.add(saveBtn);
        actionPanel.add(cancelBtn);
        add(actionPanel, BorderLayout.SOUTH);
    }
}
