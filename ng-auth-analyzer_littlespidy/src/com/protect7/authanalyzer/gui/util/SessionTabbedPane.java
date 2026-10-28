// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.util;

import java.awt.Component;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import com.protect7.authanalyzer.gui.listener.CloneSessionListener;
import com.protect7.authanalyzer.gui.listener.DeleteSessionListener;
import com.protect7.authanalyzer.gui.listener.NewSessionListener;
import com.protect7.authanalyzer.gui.listener.RenameSessionListener;

public class SessionTabbedPane extends JTabbedPane {

	private static final long serialVersionUID = -2210225276859158505L;

	public interface TabOrderChangedListener {
		void onTabOrderChanged();
	}

	private DeleteSessionListener deleteSessionListener = null;
	private RenameSessionListener renameSessionListener = null;
	private NewSessionListener newSessionListener = null;
	private CloneSessionListener cloneSessionListener = null;
	private TabOrderChangedListener tabOrderChangedListener = null;
	private boolean modifEnabled = true;

	public SessionTabbedPane() {
		super();
		addTabNewSession();
	}

	public void addDeleteSessionListener(DeleteSessionListener deleteSessionListener) {
		this.deleteSessionListener = deleteSessionListener;
	}

	public void addRenameSessionListener(RenameSessionListener renameSessionListener) {
		this.renameSessionListener = renameSessionListener;
	}

	public void addNewSessionListener(NewSessionListener newSessionListener) {
		this.newSessionListener = newSessionListener;
	}

	public void addCloneSessionListener(CloneSessionListener cloneSessionListener) {
		this.cloneSessionListener = cloneSessionListener;
	}

	public void addTabOrderChangedListener(TabOrderChangedListener tabOrderChangedListener) {
		this.tabOrderChangedListener = tabOrderChangedListener;
	}

	public void setModifEnabled(boolean modifEnabled) {
		this.modifEnabled = modifEnabled;
	}

	@Override
	public void setTitleAt(int index, String title) {
		super.setTitleAt(index, title);
		setTabComponentAt(index, new SessionTab(null, title, index));
	}

	@Override
	public void addTab(String title, Component component) {
		int index = getTabCount() - 1;
		insertTab(title, null, component, null, index);
		refreshTabComponents();
	}

	@Override
	public void removeAll() {
		super.removeAll();
		addTabNewSession();
	}

	public void addTabNewSession() {
		String text = "...";
		int location = getTabCount();
		insertTab(text, null, null, null, location);
		setTabComponentAt(location, new AddSessionTab(null, text));
		setEnabledAt(location, false);
	}

	public void refreshTabComponents() {
		for (int i = 0; i < getTabCount() - 1; i++) {
			String title = getTitleAt(i);
			Component comp = getComponentAt(i);
			setTabComponentAt(i, new SessionTab(comp, title, i));
		}
	}

	public void moveSessionTab(int fromIndex, int toIndex) {
		if (!canModify()) return;
		int maxIndex = getTabCount() - 2;
		if (fromIndex < 0 || fromIndex > maxIndex || toIndex < 0 || toIndex > maxIndex || fromIndex == toIndex) {
			return;
		}
		String title = getTitleAt(fromIndex);
		Component comp = getComponentAt(fromIndex);
		remove(fromIndex);
		insertTab(title, null, comp, null, toIndex);
		setSelectedIndex(toIndex);
		refreshTabComponents();
		if (tabOrderChangedListener != null) {
			tabOrderChangedListener.onTabOrderChanged();
		}
	}

	private int getSessionTabIndex(String title) {
		for (int i = 0; i < getTabCount() - 1; i++) {
			if (getTitleAt(i).equals(title)) {
				return i;
			}
		}
		return -1;
	}

	public class SessionTab extends JPanel {

		private static final long serialVersionUID = 3898047768157638854L;
		private Point dragStartPoint = null;
		private int dragStartIndex = -1;

		public SessionTab(final Component tab, String title, int index) {
			FlowLayout flowLayout = new FlowLayout(FlowLayout.CENTER, 3, 3);
			setLayout(flowLayout);
			JLabel titleLabel = new JLabel(title + " ");
			add(titleLabel);
			titleLabel.setToolTipText("Drag to reorder profile | Double-click to rename | Right-click for options");

			MouseAdapter mouseHandler = new MouseAdapter() {
				@Override
				public void mouseClicked(MouseEvent e) {
					int currIdx = getSessionTabIndex(title);
					if (currIdx != -1) {
						setSelectedIndex(currIdx);
					}
					if (e.getClickCount() == 2 && canModify()) {
						if (renameSessionListener != null) {
							renameSessionListener.renameSession(title);
						}
					}
				}

				@Override
				public void mousePressed(MouseEvent e) {
					int currIdx = getSessionTabIndex(title);
					if (currIdx != -1) {
						setSelectedIndex(currIdx);
					}
					if (SwingUtilities.isLeftMouseButton(e)) {
						dragStartPoint = e.getPoint();
						dragStartIndex = currIdx;
					}
					maybeShowPopup(e);
				}

				@Override
				public void mouseReleased(MouseEvent e) {
					if (SwingUtilities.isLeftMouseButton(e) && dragStartPoint != null && dragStartIndex != -1) {
						Point p = SwingUtilities.convertPoint(SessionTab.this, e.getPoint(), SessionTabbedPane.this);
						int targetIdx = SessionTabbedPane.this.indexAtLocation(p.x, p.y);
						int maxIdx = getTabCount() - 2;
						if (targetIdx >= 0 && targetIdx <= maxIdx && targetIdx != dragStartIndex) {
							moveSessionTab(dragStartIndex, targetIdx);
						}
						setCursor(Cursor.getDefaultCursor());
						dragStartPoint = null;
						dragStartIndex = -1;
					}
					maybeShowPopup(e);
				}

				@Override
				public void mouseDragged(MouseEvent e) {
					if (SwingUtilities.isLeftMouseButton(e) && dragStartPoint != null) {
						setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
					}
				}

				private void maybeShowPopup(MouseEvent e) {
					if (e.isPopupTrigger() || SwingUtilities.isRightMouseButton(e)) {
						showTabContextMenu(e, title);
					}
				}
			};

			addMouseListener(mouseHandler);
			addMouseMotionListener(mouseHandler);
			titleLabel.addMouseListener(mouseHandler);
			titleLabel.addMouseMotionListener(mouseHandler);

			JButton deleteButton = new JButton("X");
			deleteButton.setMargin(new Insets(0, 0, 0, 0));
			deleteButton.setToolTipText("Delete Session");
			deleteButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					if (canModify() && deleteSessionListener != null) {
						deleteSessionListener.deleteSession(title);
					}
				}
			});
			add(deleteButton);
		}

		private void showTabContextMenu(MouseEvent e, String title) {
			int currIdx = getSessionTabIndex(title);
			if (currIdx == -1) return;

			JPopupMenu popup = new JPopupMenu();

			JMenuItem moveLeftItem = new JMenuItem("Move Left");
			moveLeftItem.setEnabled(canModify() && currIdx > 0);
			moveLeftItem.addActionListener(ev -> moveSessionTab(currIdx, currIdx - 1));
			popup.add(moveLeftItem);

			JMenuItem moveRightItem = new JMenuItem("Move Right");
			moveRightItem.setEnabled(canModify() && currIdx < getTabCount() - 2);
			moveRightItem.addActionListener(ev -> moveSessionTab(currIdx, currIdx + 1));
			popup.add(moveRightItem);

			popup.addSeparator();

			JMenuItem renameItem = new JMenuItem("Rename Session");
			renameItem.setEnabled(canModify());
			renameItem.addActionListener(ev -> {
				if (renameSessionListener != null) {
					renameSessionListener.renameSession(title);
				}
			});
			popup.add(renameItem);

			JMenuItem cloneItem = new JMenuItem("Clone Selected Session");
			cloneItem.setEnabled(canModify());
			cloneItem.addActionListener(ev -> {
				if (cloneSessionListener != null) {
					cloneSessionListener.cloneSession();
				}
			});
			popup.add(cloneItem);

			JMenuItem deleteItem = new JMenuItem("Delete Session");
			deleteItem.setEnabled(canModify());
			deleteItem.addActionListener(ev -> {
				if (deleteSessionListener != null) {
					deleteSessionListener.deleteSession(title);
				}
			});
			popup.add(deleteItem);

			popup.show(e.getComponent(), e.getX(), e.getY());
		}
	}

	public class AddSessionTab extends JPanel {

		private static final long serialVersionUID = 9025776536297919810L;

		public AddSessionTab(final Component tab, String title) {
			setOpaque(false);
			FlowLayout flowLayout = new FlowLayout(FlowLayout.CENTER, 3, 3);
			setLayout(flowLayout);
			JLabel titleLabel = new JLabel(title);
			add(titleLabel);
			titleLabel.addMouseListener(new MouseAdapter() {
				@Override
				public void mouseReleased(MouseEvent event) {
					JPopupMenu contextMenu = new JPopupMenu();
					JMenuItem newSessionItem = new JMenuItem("Add New Session");
					newSessionItem.addActionListener(new ActionListener() {
						@Override
						public void actionPerformed(ActionEvent e) {
							if (canModify() && newSessionListener != null) {
								newSessionListener.newSession();
							}
						}
					});
					contextMenu.add(newSessionItem);
					JMenuItem cloneSessionItem = new JMenuItem("Clone Selected Session");
					cloneSessionItem.addActionListener(new ActionListener() {
						@Override
						public void actionPerformed(ActionEvent e) {
							if (canModify() && cloneSessionListener != null) {
								cloneSessionListener.cloneSession();
							}
						}
					});
					contextMenu.add(cloneSessionItem);
					contextMenu.show(event.getComponent(), event.getX(), event.getY());
				}
			});
		}
	}

	public boolean canModify() {
		return modifEnabled;
	}
}
