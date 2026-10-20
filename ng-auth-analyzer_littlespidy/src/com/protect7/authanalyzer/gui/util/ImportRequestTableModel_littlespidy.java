// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.util;

import java.util.ArrayList;
import java.util.List;
import javax.swing.SwingUtilities;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.RequestTableModel.Column;
import com.protect7.authanalyzer.util.BypassConstants;

public class ImportRequestTableModel_littlespidy extends RequestTableModel {

	private static final long serialVersionUID = 1L;
	private final ArrayList<OriginalRequestResponse> originalRequestResponseList = new ArrayList<OriginalRequestResponse>();
	private final ArrayList<Session> sessions = new ArrayList<Session>();
	private final int STATIC_COLUMN_COUNT = 7;

	public void setImportedData(List<OriginalRequestResponse> originals, List<Session> importedSessions) {
		originalRequestResponseList.clear();
		sessions.clear();
		if (originals != null) {
			originalRequestResponseList.addAll(originals);
		}
		if (importedSessions != null) {
			sessions.addAll(importedSessions);
		}
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				fireTableStructureChanged();
			}
		});
	}

	@Override
	public ArrayList<OriginalRequestResponse> getOriginalRequestResponseList() {
		return originalRequestResponseList;
	}

	public ArrayList<Session> getSessions() {
		return sessions;
	}

	public void clear() {
		originalRequestResponseList.clear();
		sessions.clear();
		fireTableStructureChanged();
	}

	@Override
	public void clearRequestMap() {
		clear();
	}

	@Override
	public void deleteRequestResponse(OriginalRequestResponse requestResponse) {
		originalRequestResponseList.remove(requestResponse);
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				fireTableDataChanged();
			}
		});
	}

	@Override
	public boolean isDuplicate(int id, String endpoint) {
		for(OriginalRequestResponse requestResponse : originalRequestResponseList) {
			if(requestResponse.getEndpoint().equals(endpoint) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}

	@Override
	public OriginalRequestResponse getOriginalRequestResponse(int listIndex) {
		if(listIndex >= 0 && listIndex < originalRequestResponseList.size()) {
			return originalRequestResponseList.get(listIndex);
		}
		return null;
	}

	@Override
	public OriginalRequestResponse getOriginalRequestResponseById(int id) {
		for(OriginalRequestResponse requestResponse : originalRequestResponseList) {
			if(requestResponse.getId() == id) {
				return requestResponse;
			}
		}
		return null;
	}

	@Override
	public int getColumnCount() {
		return STATIC_COLUMN_COUNT + (sessions.size() * 4);
	}

	@Override
	public int getRowCount() {
		return originalRequestResponseList.size();
	}

	@Override
	public Object getValueAt(int row, int column) {
		if(row >= originalRequestResponseList.size()) {
			return null;
		}
		OriginalRequestResponse originalRequestResponse = originalRequestResponseList.get(row);
		int tempColunmIndex = 4;
		if(column == 0) return originalRequestResponse.getId();
		if(column == 1) return originalRequestResponse.getMethod();
		if(column == 2) return originalRequestResponse.getHost();
		if(column == 3) return originalRequestResponse.getUrl();
		if(column == 4) return originalRequestResponse.getStatusCode();
		
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				AnalyzerRequestResponse map = sessions.get(i).getRequestResponseMap().get(originalRequestResponse.getId());
				return map != null ? map.getStatusCode() : -1;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return originalRequestResponse.getResponseContentLength();
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				AnalyzerRequestResponse map = sessions.get(i).getRequestResponseMap().get(originalRequestResponse.getId());
				return map != null ? map.getResponseContentLength() : -1;
			}
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				AnalyzerRequestResponse map = sessions.get(i).getRequestResponseMap().get(originalRequestResponse.getId());
				int sLen = map != null ? map.getResponseContentLength() : 0;
				return originalRequestResponse.getResponseContentLength() - sLen;
			}
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				AnalyzerRequestResponse map = sessions.get(i).getRequestResponseMap().get(originalRequestResponse.getId());
				return map != null ? map.getStatus() : BypassConstants.NA;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return originalRequestResponse.getComment();
		}
		return null;
	}

	@Override
	public String getColumnName(int column) {
		int tempColunmIndex = 4;
		if(column == 0) return Column.ID.toString();
		if(column == 1) return Column.Method.toString();
		if(column == 2) return Column.Host.toString();
		if(column == 3) return Column.Path.toString();
		if(column == 4) return Column.Code.toString();
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return sessions.get(i).getName() + " " + Column.Code;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) return Column.Length.toString();
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return sessions.get(i).getName() + " " + Column.Length;
			}
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return sessions.get(i).getName() + " " + Column.Diff;
			}
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return sessions.get(i).getName() + " " + Column.Status;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) return Column.Comment.toString();
		return "";
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		int tempColunmIndex = 4;
		if(columnIndex <= 0) return Integer.class;
		if(columnIndex <= 3) return String.class;
		if(columnIndex == 4) return Integer.class;
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) return Integer.class;
		}
		tempColunmIndex++;
		if(columnIndex == tempColunmIndex) return Integer.class;
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) return Integer.class;
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) return Integer.class;
		}
		for(int i=0; i<sessions.size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) return BypassConstants.class;
		}
		tempColunmIndex++;
		if(columnIndex == tempColunmIndex) return String.class;
		return Object.class;
	}
}
