// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.util;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;

public class MethodFilterDropDown_littlespidy extends JButton {

	private static final long serialVersionUID = 1L;
	private static final List<String> METHODS = Arrays.asList(
			"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"
	);

	private final Map<String, JCheckBox> methodCheckBoxMap = new LinkedHashMap<String, JCheckBox>();
	private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
	private final JPopupMenu popupMenu = new JPopupMenu();
	private final List<Runnable> listeners = new ArrayList<Runnable>();
	private boolean updatingProgrammatically = false;

	public MethodFilterDropDown_littlespidy() {
		super("Methods: All");
		initUI();
	}

	private void initUI() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

		selectAllCheckBox.addActionListener(e -> {
			if (updatingProgrammatically) {
				return;
			}
			boolean selected = selectAllCheckBox.isSelected();
			updatingProgrammatically = true;
			for (JCheckBox cb : methodCheckBoxMap.values()) {
				cb.setSelected(selected);
			}
			updatingProgrammatically = false;
			updateButtonLabel();
			notifyListeners();
		});
		panel.add(selectAllCheckBox);
		panel.add(new JSeparator());

		ActionListener itemListener = e -> {
			if (updatingProgrammatically) {
				return;
			}
			syncSelectAllState();
			updateButtonLabel();
			notifyListeners();
		};

		for (String method : METHODS) {
			JCheckBox cb = new JCheckBox(method, true);
			cb.addActionListener(itemListener);
			methodCheckBoxMap.put(method, cb);
			panel.add(cb);
		}

		popupMenu.add(panel);

		addActionListener(e -> {
			if (popupMenu.isVisible()) {
				popupMenu.setVisible(false);
			} else {
				popupMenu.show(this, 0, getHeight());
			}
		});
		updateButtonLabel();
	}

	private void syncSelectAllState() {
		int selectedCount = 0;
		for (JCheckBox cb : methodCheckBoxMap.values()) {
			if (cb.isSelected()) {
				selectedCount++;
			}
		}
		updatingProgrammatically = true;
		selectAllCheckBox.setSelected(selectedCount == methodCheckBoxMap.size());
		updatingProgrammatically = false;
	}

	private void updateButtonLabel() {
		List<String> selected = new ArrayList<String>();
		for (Map.Entry<String, JCheckBox> entry : methodCheckBoxMap.entrySet()) {
			if (entry.getValue().isSelected()) {
				selected.add(entry.getKey());
			}
		}
		if (selected.size() == methodCheckBoxMap.size()) {
			setText("Methods: All");
		} else if (selected.isEmpty()) {
			setText("Methods: None");
		} else if (selected.size() <= 2) {
			setText("Methods: " + String.join(", ", selected));
		} else {
			setText("Methods: (" + selected.size() + "/" + methodCheckBoxMap.size() + ")");
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

	public boolean isMethodSelected(String method) {
		if (method == null || method.trim().isEmpty()) {
			return true;
		}
		String normalized = method.trim().toUpperCase(Locale.ROOT);
		JCheckBox cb = methodCheckBoxMap.get(normalized);
		if (cb != null) {
			return cb.isSelected();
		}
		// If method is non-standard (e.g. TRACE, CONNECT, PROPFIND), show if Select All or any standard is selected
		return selectAllCheckBox.isSelected();
	}

	public Set<String> getSelectedMethods() {
		Set<String> set = new HashSet<String>();
		for (Map.Entry<String, JCheckBox> entry : methodCheckBoxMap.entrySet()) {
			if (entry.getValue().isSelected()) {
				set.add(entry.getKey());
			}
		}
		return set;
	}

	public void setMethodSelected(String method, boolean selected) {
		if (method == null) return;
		JCheckBox cb = methodCheckBoxMap.get(method.toUpperCase(Locale.ROOT));
		if (cb != null) {
			cb.setSelected(selected);
			syncSelectAllState();
			updateButtonLabel();
			notifyListeners();
		}
	}

	public void selectAll() {
		updatingProgrammatically = true;
		selectAllCheckBox.setSelected(true);
		for (JCheckBox cb : methodCheckBoxMap.values()) {
			cb.setSelected(true);
		}
		updatingProgrammatically = false;
		updateButtonLabel();
		notifyListeners();
	}

	public void selectNone() {
		updatingProgrammatically = true;
		selectAllCheckBox.setSelected(false);
		for (JCheckBox cb : methodCheckBoxMap.values()) {
			cb.setSelected(false);
		}
		updatingProgrammatically = false;
		updateButtonLabel();
		notifyListeners();
	}
}
