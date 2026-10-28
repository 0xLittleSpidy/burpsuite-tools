// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.util;

import java.awt.Dimension;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;

public class AcaoFilterDropDown_littlespidy extends JButton {

	private static final long serialVersionUID = 1L;
	public static final String NONE_KEY = "(None)";
	private final Map<String, JCheckBox> acaoCheckBoxMap = new LinkedHashMap<String, JCheckBox>();
	private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
	private final JPopupMenu popupMenu = new JPopupMenu();
	private final JPanel itemsPanel = new JPanel();
	private final List<Runnable> listeners = new ArrayList<Runnable>();
	private boolean updatingProgrammatically = false;

	public AcaoFilterDropDown_littlespidy() {
		super("Reflected ACAO: All");
		initUI();
	}

	private void initUI() {
		JPanel mainPopupPanel = new JPanel();
		mainPopupPanel.setLayout(new BoxLayout(mainPopupPanel, BoxLayout.Y_AXIS));
		mainPopupPanel.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

		selectAllCheckBox.addActionListener(e -> {
			if (updatingProgrammatically) {
				return;
			}
			boolean selected = selectAllCheckBox.isSelected();
			updatingProgrammatically = true;
			for (JCheckBox cb : acaoCheckBoxMap.values()) {
				cb.setSelected(selected);
			}
			updatingProgrammatically = false;
			updateButtonLabel();
			notifyListeners();
		});
		mainPopupPanel.add(selectAllCheckBox);
		mainPopupPanel.add(new JSeparator());

		itemsPanel.setLayout(new BoxLayout(itemsPanel, BoxLayout.Y_AXIS));
		JScrollPane scrollPane = new JScrollPane(itemsPanel,
				JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
				JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		scrollPane.setBorder(null);
		scrollPane.setPreferredSize(new Dimension(240, 160));
		mainPopupPanel.add(scrollPane);

		popupMenu.add(mainPopupPanel);

		addActionListener(e -> {
			if (popupMenu.isVisible()) {
				popupMenu.setVisible(false);
			} else {
				popupMenu.show(this, 0, getHeight());
			}
		});
		updateButtonLabel();
	}

	public synchronized void updateAcaoValues(Collection<String> rawValues) {
		if (rawValues == null) {
			return;
		}
		boolean changed = false;
		for (String raw : rawValues) {
			String key = normalizeAcao(raw);
			if (!acaoCheckBoxMap.containsKey(key)) {
				JCheckBox cb = new JCheckBox(key, selectAllCheckBox.isSelected());
				cb.addActionListener(e -> {
					if (updatingProgrammatically) {
						return;
					}
					syncSelectAllState();
					updateButtonLabel();
					notifyListeners();
				});
				acaoCheckBoxMap.put(key, cb);
				itemsPanel.add(cb);
				changed = true;
			}
		}
		if (changed) {
			itemsPanel.revalidate();
			itemsPanel.repaint();
			syncSelectAllState();
			updateButtonLabel();
		}
	}

	private void syncSelectAllState() {
		int selectedCount = 0;
		for (JCheckBox cb : acaoCheckBoxMap.values()) {
			if (cb.isSelected()) {
				selectedCount++;
			}
		}
		updatingProgrammatically = true;
		selectAllCheckBox.setSelected(!acaoCheckBoxMap.isEmpty() && selectedCount == acaoCheckBoxMap.size());
		updatingProgrammatically = false;
	}

	private void updateButtonLabel() {
		List<String> selected = new ArrayList<String>();
		for (Map.Entry<String, JCheckBox> entry : acaoCheckBoxMap.entrySet()) {
			if (entry.getValue().isSelected()) {
				selected.add(entry.getKey());
			}
		}
		if (acaoCheckBoxMap.isEmpty() || selected.size() == acaoCheckBoxMap.size()) {
			setText("Reflected ACAO: All");
		} else if (selected.isEmpty()) {
			setText("Reflected ACAO: None");
		} else if (selected.size() == 1) {
			setText("Reflected ACAO: " + selected.get(0));
		} else if (selected.size() == 2) {
			setText("Reflected ACAO: " + selected.get(0) + ", " + selected.get(1));
		} else {
			setText("Reflected ACAO: (" + selected.size() + "/" + acaoCheckBoxMap.size() + ")");
		}
	}

	public void addFilterChangeListener(Runnable listener) {
		if (listener != null) {
			listeners.add(listener);
		}
	}

	private void notifyListeners() {
		for (Runnable listener : listeners) {
			try {
				listener.run();
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
	}

	public boolean isAcaoSelected(String raw) {
		if (acaoCheckBoxMap.isEmpty()) {
			return true;
		}
		String key = normalizeAcao(raw);
		JCheckBox cb = acaoCheckBoxMap.get(key);
		if (cb != null) {
			return cb.isSelected();
		}
		return selectAllCheckBox.isSelected();
	}

	public static String normalizeAcao(String raw) {
		if (raw == null || raw.trim().isEmpty()) {
			return NONE_KEY;
		}
		return raw.trim();
	}

	public Set<String> getSelectedAcaoValues() {
		Set<String> set = new HashSet<String>();
		for (Map.Entry<String, JCheckBox> entry : acaoCheckBoxMap.entrySet()) {
			if (entry.getValue().isSelected()) {
				set.add(entry.getKey());
			}
		}
		return set;
	}

	public synchronized void clear() {
		updatingProgrammatically = true;
		acaoCheckBoxMap.clear();
		itemsPanel.removeAll();
		selectAllCheckBox.setSelected(true);
		updatingProgrammatically = false;
		itemsPanel.revalidate();
		itemsPanel.repaint();
		updateButtonLabel();
	}
}
