// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.util;

import java.awt.Dimension;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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

public class DomainFilterDropDown_littlespidy extends JButton {

	private static final long serialVersionUID = 1L;
	private final Map<String, JCheckBox> domainCheckBoxMap = new LinkedHashMap<String, JCheckBox>();
	private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
	private final JPopupMenu popupMenu = new JPopupMenu();
	private final JPanel itemsPanel = new JPanel();
	private final List<Runnable> listeners = new ArrayList<Runnable>();
	private boolean updatingProgrammatically = false;

	public DomainFilterDropDown_littlespidy() {
		super("Domains: All");
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
			for (JCheckBox cb : domainCheckBoxMap.values()) {
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
		scrollPane.setPreferredSize(new Dimension(220, 160));
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

	public synchronized void updateDomains(Collection<String> domains) {
		if (domains == null) {
			return;
		}
		boolean changed = false;
		for (String raw : domains) {
			if (raw == null || raw.trim().isEmpty()) {
				continue;
			}
			String domain = raw.trim().toLowerCase(Locale.ROOT);
			if (!domainCheckBoxMap.containsKey(domain)) {
				JCheckBox cb = new JCheckBox(domain, selectAllCheckBox.isSelected());
				cb.addActionListener(e -> {
					if (updatingProgrammatically) {
						return;
					}
					syncSelectAllState();
					updateButtonLabel();
					notifyListeners();
				});
				domainCheckBoxMap.put(domain, cb);
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
		for (JCheckBox cb : domainCheckBoxMap.values()) {
			if (cb.isSelected()) {
				selectedCount++;
			}
		}
		updatingProgrammatically = true;
		selectAllCheckBox.setSelected(!domainCheckBoxMap.isEmpty() && selectedCount == domainCheckBoxMap.size());
		updatingProgrammatically = false;
	}

	private void updateButtonLabel() {
		List<String> selected = new ArrayList<String>();
		for (Map.Entry<String, JCheckBox> entry : domainCheckBoxMap.entrySet()) {
			if (entry.getValue().isSelected()) {
				selected.add(entry.getKey());
			}
		}
		if (domainCheckBoxMap.isEmpty() || selected.size() == domainCheckBoxMap.size()) {
			setText("Domains: All");
		} else if (selected.isEmpty()) {
			setText("Domains: None");
		} else if (selected.size() == 1) {
			setText("Domains: " + selected.get(0));
		} else if (selected.size() == 2) {
			setText("Domains: " + selected.get(0) + ", " + selected.get(1));
		} else {
			setText("Domains: (" + selected.size() + "/" + domainCheckBoxMap.size() + ")");
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

	public boolean isDomainSelected(String domain) {
		if (domainCheckBoxMap.isEmpty() || domain == null || domain.trim().isEmpty()) {
			return true;
		}
		String normalized = domain.trim().toLowerCase(Locale.ROOT);
		JCheckBox cb = domainCheckBoxMap.get(normalized);
		if (cb != null) {
			return cb.isSelected();
		}
		return selectAllCheckBox.isSelected();
	}

	public Set<String> getSelectedDomains() {
		Set<String> set = new HashSet<String>();
		for (Map.Entry<String, JCheckBox> entry : domainCheckBoxMap.entrySet()) {
			if (entry.getValue().isSelected()) {
				set.add(entry.getKey());
			}
		}
		return set;
	}

	public void setDomainSelected(String domain, boolean selected) {
		if (domain == null) return;
		JCheckBox cb = domainCheckBoxMap.get(domain.toLowerCase(Locale.ROOT));
		if (cb != null) {
			cb.setSelected(selected);
			syncSelectAllState();
			updateButtonLabel();
			notifyListeners();
		}
	}

	public void clear() {
		domainCheckBoxMap.clear();
		itemsPanel.removeAll();
		itemsPanel.revalidate();
		itemsPanel.repaint();
		selectAllCheckBox.setSelected(true);
		updateButtonLabel();
		notifyListeners();
	}
}
