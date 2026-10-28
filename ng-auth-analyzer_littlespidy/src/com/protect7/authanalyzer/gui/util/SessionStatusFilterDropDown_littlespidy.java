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
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.Session;

public class SessionStatusFilterDropDown_littlespidy extends JButton {

	private static final long serialVersionUID = 1L;
	private final Map<String, JCheckBox> statusCheckBoxMap = new LinkedHashMap<String, JCheckBox>();
	// Map sessionName -> Set of observed status codes
	private final Map<String, Set<Integer>> sessionObservedMap = new LinkedHashMap<String, Set<Integer>>();
	private final JCheckBox selectAllCheckBox = new JCheckBox("Select All", true);
	private final JPopupMenu popupMenu = new JPopupMenu();
	private final JPanel itemsPanel = new JPanel();
	private final List<Runnable> listeners = new ArrayList<Runnable>();
	private boolean updatingProgrammatically = false;

	public SessionStatusFilterDropDown_littlespidy() {
		super("User/Status: All");
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
			for (JCheckBox cb : statusCheckBoxMap.values()) {
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
		scrollPane.setPreferredSize(new Dimension(240, 180));
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

	public synchronized void updateSessionStatuses(Map<String, Set<Integer>> newMap) {
		if (newMap == null || newMap.isEmpty()) {
			clear();
			return;
		}

		// Calculate all valid target keys
		Set<String> targetKeys = new HashSet<String>();
		for (Map.Entry<String, Set<Integer>> entry : newMap.entrySet()) {
			String sessionName = entry.getKey();
			if (sessionName == null || sessionName.trim().isEmpty() || "original".equalsIgnoreCase(sessionName.trim())) {
				continue;
			}
			for (Integer code : entry.getValue()) {
				if (code != null && code > 0) {
					targetKeys.add(buildKey(sessionName, code));
				}
			}
		}

		if (targetKeys.isEmpty()) {
			clear();
			return;
		}

		boolean changed = false;

		// 1. Remove obsolete keys that are no longer present in targetKeys
		List<String> keysToRemove = new ArrayList<String>();
		for (String existingKey : statusCheckBoxMap.keySet()) {
			if (!targetKeys.contains(existingKey)) {
				keysToRemove.add(existingKey);
			}
		}
		for (String key : keysToRemove) {
			JCheckBox cb = statusCheckBoxMap.remove(key);
			if (cb != null) {
				itemsPanel.remove(cb);
				changed = true;
			}
		}

		// 2. Add new keys
		for (Map.Entry<String, Set<Integer>> entry : newMap.entrySet()) {
			String sessionName = entry.getKey();
			if (sessionName == null || sessionName.trim().isEmpty() || "original".equalsIgnoreCase(sessionName.trim())) {
				continue;
			}
			for (Integer code : entry.getValue()) {
				if (code == null || code <= 0) {
					continue;
				}
				String key = buildKey(sessionName, code);
				if (!statusCheckBoxMap.containsKey(key)) {
					JCheckBox cb = new JCheckBox(key, selectAllCheckBox.isSelected());
					cb.addActionListener(e -> {
						if (updatingProgrammatically) {
							return;
						}
						syncSelectAllState();
						updateButtonLabel();
						notifyListeners();
					});
					statusCheckBoxMap.put(key, cb);
					itemsPanel.add(cb);
					changed = true;
				}
			}
		}

		// 3. Rebuild sessionObservedMap to exactly mirror newMap
		sessionObservedMap.clear();
		for (Map.Entry<String, Set<Integer>> entry : newMap.entrySet()) {
			String sName = entry.getKey();
			if (sName != null && !sName.trim().isEmpty() && !"original".equalsIgnoreCase(sName.trim())) {
				Set<Integer> validCodes = new HashSet<Integer>();
				for (Integer c : entry.getValue()) {
					if (c != null && c > 0) {
						validCodes.add(c);
					}
				}
				if (!validCodes.isEmpty()) {
					sessionObservedMap.put(sName, validCodes);
				}
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
		for (JCheckBox cb : statusCheckBoxMap.values()) {
			if (cb.isSelected()) {
				selectedCount++;
			}
		}
		updatingProgrammatically = true;
		selectAllCheckBox.setSelected(!statusCheckBoxMap.isEmpty() && selectedCount == statusCheckBoxMap.size());
		updatingProgrammatically = false;
	}

	private void updateButtonLabel() {
		List<String> selected = new ArrayList<String>();
		for (Map.Entry<String, JCheckBox> entry : statusCheckBoxMap.entrySet()) {
			if (entry.getValue().isSelected()) {
				selected.add(entry.getKey());
			}
		}
		if (statusCheckBoxMap.isEmpty() || selected.size() == statusCheckBoxMap.size()) {
			setText("User/Status: All");
		} else if (selected.isEmpty()) {
			setText("User/Status: None");
		} else if (selected.size() == 1) {
			setText("User/Status: " + selected.get(0));
		} else {
			setText("User/Status: (" + selected.size() + "/" + statusCheckBoxMap.size() + ")");
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

	public static String buildKey(String sessionName, int statusCode) {
		return sessionName + " - " + statusCode;
	}

	/**
	 * Checks if a row matches the session-status filter.
	 * Session-grouped logic:
	 * AND across different sessions, OR within the same session.
	 * If all status codes for a session are selected, that session imposes no constraint.
	 */
	public boolean isRowMatching(int requestId, List<Session> sessions) {
		if (statusCheckBoxMap.isEmpty() || selectAllCheckBox.isSelected()) {
			return true;
		}
		if (sessions == null || sessions.isEmpty()) {
			return true;
		}

		// Check if any box is checked at all
		boolean anyChecked = false;
		for (JCheckBox cb : statusCheckBoxMap.values()) {
			if (cb.isSelected()) {
				anyChecked = true;
				break;
			}
		}
		if (!anyChecked) {
			return false;
		}

		for (Session session : sessions) {
			if (session == null || session.getName() == null) {
				continue;
			}
			String sessionName = session.getName();
			Set<Integer> allObserved = sessionObservedMap.get(sessionName);
			if (allObserved == null || allObserved.isEmpty()) {
				continue;
			}

			// Gather checked status codes for this session
			Set<Integer> selectedCodesForSession = new HashSet<Integer>();
			for (Integer code : allObserved) {
				String key = buildKey(sessionName, code);
				JCheckBox cb = statusCheckBoxMap.get(key);
				if (cb != null && cb.isSelected()) {
					selectedCodesForSession.add(code);
				}
			}

			// If none of this session's codes are checked, row fails this session constraint
			if (selectedCodesForSession.isEmpty()) {
				return false;
			}

			// If not all codes are checked, this session is constrained
			if (selectedCodesForSession.size() < allObserved.size()) {
				AnalyzerRequestResponse arr = session.getRequestResponseMap().get(requestId);
				if (arr == null) {
					return false;
				}
				int rowStatusCode = arr.getStatusCode();
				if (!selectedCodesForSession.contains(rowStatusCode)) {
					return false;
				}
			}
		}
		return true;
	}

	public synchronized void clear() {
		updatingProgrammatically = true;
		statusCheckBoxMap.clear();
		sessionObservedMap.clear();
		itemsPanel.removeAll();
		selectAllCheckBox.setSelected(true);
		updatingProgrammatically = false;
		itemsPanel.revalidate();
		itemsPanel.repaint();
		updateButtonLabel();
	}
}
