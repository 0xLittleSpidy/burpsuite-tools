// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.cors;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Window;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import com.protect7.authanalyzer.cors.CorsEngine_littlespidy;
import com.protect7.authanalyzer.cors.CorsEngine_littlespidy.TestVector;

public class CorsTechniquesDialog_littlespidy extends JDialog {

	private static final long serialVersionUID = 1L;
	private final JTextField attackerUrlField = new JTextField(18);
	private final List<TestVector> allVectors;
	private final Set<String> enabledTechniqueIds = new HashSet<String>();
	private final TechniquesTableModel tableModel;
	private final JTable table;

	public CorsTechniquesDialog_littlespidy(Component parent, String currentAttackerUrl, Set<String> currentEnabledIds) {
		super(SwingUtilities.getWindowAncestor(parent), "PortSwigger 29 CORS Bypass Techniques", ModalityType.APPLICATION_MODAL);
		setLayout(new BorderLayout(8, 8));
		setSize(850, 520);
		setLocationRelativeTo(parent);

		allVectors = CorsEngine_littlespidy.generateTestVectors("example.com", "evil.com");
		if (currentEnabledIds != null && !currentEnabledIds.isEmpty()) {
			enabledTechniqueIds.addAll(currentEnabledIds);
		} else {
			for (TestVector v : allVectors) {
				enabledTechniqueIds.add(v.id);
			}
		}

		tableModel = new TechniquesTableModel();
		table = new JTable(tableModel);

		attackerUrlField.setText(currentAttackerUrl != null && !currentAttackerUrl.trim().isEmpty() ? currentAttackerUrl.trim() : "evil.com");

		// Top panel: Attacker URL + Select All / Deselect All
		JPanel topPanel = new JPanel(new BorderLayout(8, 0));
		topPanel.setBorder(BorderFactory.createEmptyBorder(8, 10, 4, 10));

		JPanel leftTop = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
		leftTop.add(new JLabel("CORS Attacker URL:"));
		leftTop.add(attackerUrlField);
		topPanel.add(leftTop, BorderLayout.WEST);

		JPanel rightTop = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
		JButton selectAllBtn = new JButton("Select All");
		selectAllBtn.addActionListener(e -> {
			for (TestVector v : allVectors) {
				enabledTechniqueIds.add(v.id);
			}
			tableModel.fireTableDataChanged();
		});

		JButton deselectAllBtn = new JButton("Deselect All");
		deselectAllBtn.addActionListener(e -> {
			enabledTechniqueIds.clear();
			tableModel.fireTableDataChanged();
		});

		JButton resetDefaultsBtn = new JButton("Reset Defaults");
		resetDefaultsBtn.addActionListener(e -> {
			enabledTechniqueIds.clear();
			for (TestVector v : allVectors) {
				enabledTechniqueIds.add(v.id);
			}
			attackerUrlField.setText("evil.com");
			tableModel.fireTableDataChanged();
		});

		rightTop.add(selectAllBtn);
		rightTop.add(deselectAllBtn);
		rightTop.add(resetDefaultsBtn);
		topPanel.add(rightTop, BorderLayout.EAST);

		add(topPanel, BorderLayout.NORTH);

		// Center Table
		table.setRowHeight(24);
		table.getColumnModel().getColumn(0).setPreferredWidth(55);
		table.getColumnModel().getColumn(0).setMaxWidth(60);
		table.getColumnModel().getColumn(1).setPreferredWidth(210);
		table.getColumnModel().getColumn(2).setPreferredWidth(240);
		table.getColumnModel().getColumn(3).setPreferredWidth(280);

		table.setDefaultRenderer(Boolean.class, table.getDefaultRenderer(Boolean.class));
		JScrollPane scrollPane = new JScrollPane(table);
		scrollPane.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
		add(scrollPane, BorderLayout.CENTER);

		// Bottom panel: Close button
		JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 8));
		JButton saveCloseBtn = new JButton("Save and Close");
		saveCloseBtn.addActionListener(e -> setVisible(false));
		bottomPanel.add(saveCloseBtn);
		add(bottomPanel, BorderLayout.SOUTH);
	}

	public String getAttackerUrl() {
		String val = attackerUrlField.getText();
		return val != null && !val.trim().isEmpty() ? val.trim() : "evil.com";
	}

	public Set<String> getEnabledTechniqueIds() {
		return new HashSet<String>(enabledTechniqueIds);
	}

	private class TechniquesTableModel extends AbstractTableModel {
		private static final long serialVersionUID = 1L;
		private final String[] columns = { "Active", "Technique Name", "Origin Vector Pattern", "Browser / Context Note" };

		@Override
		public int getRowCount() {
			return allVectors.size();
		}

		@Override
		public int getColumnCount() {
			return columns.length;
		}

		@Override
		public String getColumnName(int col) {
			return columns[col];
		}

		@Override
		public Class<?> getColumnClass(int col) {
			return col == 0 ? Boolean.class : String.class;
		}

		@Override
		public boolean isCellEditable(int row, int col) {
			return col == 0;
		}

		@Override
		public Object getValueAt(int row, int col) {
			TestVector v = allVectors.get(row);
			switch (col) {
				case 0:
					return enabledTechniqueIds.contains(v.id);
				case 1:
					return v.name;
				case 2:
					return v.origin;
				case 3:
					return v.browserNote;
				default:
					return null;
			}
		}

		@Override
		public void setValueAt(Object aValue, int row, int col) {
			if (col == 0 && aValue instanceof Boolean) {
				TestVector v = allVectors.get(row);
				if ((Boolean) aValue) {
					enabledTechniqueIds.add(v.id);
				} else {
					enabledTechniqueIds.remove(v.id);
				}
				fireTableCellUpdated(row, col);
			}
		}
	}
}
