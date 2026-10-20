// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.main;

import java.awt.Component;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.IMessageEditor;

public class RequestResponsePanel extends JTabbedPane {
	
	private static final long serialVersionUID = 5940984512441844430L;
	public final String TITLE_ORIGINAL = "Original";
	private final HashMap<String, SessionTabbedPane> sessionTabbedPaneMap = new HashMap<String, SessionTabbedPane>();
	private final CenterPanel centerPanel;
	private final int paneId;
	private int selectedIndex = 0;
	
	public RequestResponsePanel(int paneId, CenterPanel centerPanel) {
		this.paneId = paneId;
		this.centerPanel = centerPanel;
		init();
		addChangeListener(e -> {
			SessionTabbedPane sessionTabbedPane = getSelectedSessionTabbedPane();
			if(sessionTabbedPane != null && sessionTabbedPane.getTabCount() == 2) {
				if(sessionTabbedPane.getSelectedIndex() != selectedIndex) {
					sessionTabbedPane.setSelectedIndex(selectedIndex);
				}
				else {
					centerPanel.updateDiffPane();
				}
			}
		});
	}

	public void initWithSessions(List<String> sessionNames) {
		removeAll();
		sessionTabbedPaneMap.clear();
		SessionTabbedPane originalSessionTabbedPane = new SessionTabbedPane(TITLE_ORIGINAL);
		add(TITLE_ORIGINAL, originalSessionTabbedPane);
		sessionTabbedPaneMap.put(TITLE_ORIGINAL, originalSessionTabbedPane);
		if (sessionNames != null) {
			for(String name : sessionNames) {
				SessionTabbedPane sessionTabbedPane = new SessionTabbedPane(name);
				add(name, sessionTabbedPane);
				sessionTabbedPaneMap.put(name, sessionTabbedPane);
			}
		}
		setViewMode(selectedIndex);
		if(paneId == 1 && getTabCount() > 1) {
			setSelectedIndex(1);
		}
	}

	public void init() {
		ArrayList<String> names = new ArrayList<String>();
		for(Session session : CurrentConfig.getCurrentConfig().getSessions()) {
			names.add(session.getName());
		}
		initWithSessions(names);
	}

	public void setViewMode(int mode) {
		this.selectedIndex = mode;
		for(SessionTabbedPane pane : sessionTabbedPaneMap.values()) {
			if(pane.getTabCount() > mode && pane.getSelectedIndex() != mode) {
				pane.setSelectedIndex(mode);
			}
		}
	}
	
	public int getViewMode() {
		return selectedIndex;
	}
	
	public void setRequestMessage(String sessionName, Component component, IMessageEditor messageEditor) {
		if(sessionTabbedPaneMap.containsKey(sessionName)) {
			sessionTabbedPaneMap.get(sessionName).setRequestMessage(component, messageEditor);
		}
	}
	
	public void setResponseMessage(String sessionName, Component component, IMessageEditor messageEditor) {
		if(sessionTabbedPaneMap.containsKey(sessionName)) {
			sessionTabbedPaneMap.get(sessionName).setResponseMessage(component, messageEditor);
		}
	}
	
	public String getSelectedSession() {
		if (getSelectedIndex() >= 0 && getSelectedIndex() < getTabCount()) {
			return getTitleAt(getSelectedIndex());
		}
		return null;
	}
	
	public String getSelectedMessage() {
		SessionTabbedPane sessionTabbedPane = getSelectedSessionTabbedPane();
		if(sessionTabbedPane != null && sessionTabbedPane.getSelectedIndex() >= 0) {
			return sessionTabbedPane.getTitleAt(sessionTabbedPane.getSelectedIndex());
		}
		return null;
	}
	
	public SessionTabbedPane getSelectedSessionTabbedPane() {
		Component comp = getSelectedComponent();
		if (comp instanceof SessionTabbedPane) {
			return (SessionTabbedPane) comp;
		}
		return null;
	}
	
	public String getCurrentMessageString() {
		SessionTabbedPane sessionTabbedPane = getSelectedSessionTabbedPane();
		if(sessionTabbedPane != null) {
			return sessionTabbedPane.getCurrentMessageString();
		}
		return null;
	}
	
	public boolean setTabbedPaneIndex(int index) {
		SessionTabbedPane sessionTabbedPane = getSelectedSessionTabbedPane();
		if(sessionTabbedPane != null) {
			if(sessionTabbedPane.getSelectedIndex() != index) {
				if(sessionTabbedPane.getTabCount() > index) {
					sessionTabbedPane.setSelectedIndex(index);
					return true;
				}
			}
		}
		return false;
	}
	
	private class SessionTabbedPane extends JTabbedPane {
		
		private static final long serialVersionUID = -4100725845615986632L;
		private final String TITLE_REQUEST = "Request";
		private final String TITLE_RESPONSE = "Response";
		private IMessageEditor requestMessageEditor = null;
		private IMessageEditor responseMessageEditor = null;
		
		public SessionTabbedPane(String name) {
			add(TITLE_REQUEST, new JPanel());
			add(TITLE_RESPONSE, new JPanel());
			addChangeListener(e -> {
				selectedIndex = getSelectedIndex();
				centerPanel.notifyViewModeChanged(selectedIndex);
				centerPanel.updateOtherTabbedPane(paneId, getSelectedIndex());
			});
		}
		
		public void setRequestMessage(Component component, IMessageEditor messageEditor) {
			requestMessageEditor = messageEditor;
			setComponentAt(0, component);
		}
		
		public void setResponseMessage(Component component, IMessageEditor messageEditor) {
			responseMessageEditor = messageEditor;
			setComponentAt(1, component);
		}
		
		public String getCurrentMessageString() {
			if(getSelectedIndex() == 0) {
				if(requestMessageEditor != null && requestMessageEditor.getMessage() != null) {
					return new String(requestMessageEditor.getMessage());
				}
			}
			if(getSelectedIndex() == 1) {
				if(responseMessageEditor != null && responseMessageEditor.getMessage() != null) {
					return new String(responseMessageEditor.getMessage());
				}
			}
			return null;
		}
	}
}
