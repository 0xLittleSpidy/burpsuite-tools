// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.gui.util;

import java.util.Collections;
import java.util.List;
import javax.swing.JCheckBox;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.TableRowSorter;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.main.CenterPanel;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

public class CustomRowSorter extends TableRowSorter<RequestTableModel> {
	
	public CustomRowSorter(CenterPanel centerPanel, RequestTableModel tableModel, JCheckBox showOnlyMarked, JCheckBox showDuplicates, JCheckBox showBypassed, 
			JCheckBox showPotentialBypassed, JCheckBox showNotBypassed, JCheckBox showNA, PlaceholderTextField filterText,
			JCheckBox searchInPath, JCheckBox searchInRequest, JCheckBox searchInResponse, JCheckBox negativeSearch) {
		this(centerPanel, tableModel, showOnlyMarked, showDuplicates, showBypassed, showPotentialBypassed, showNotBypassed, showNA, filterText,
				searchInPath, searchInRequest, searchInResponse, negativeSearch, null, null);
	}

	public CustomRowSorter(CenterPanel centerPanel, RequestTableModel tableModel, JCheckBox showOnlyMarked, JCheckBox showDuplicates, JCheckBox showBypassed, 
			JCheckBox showPotentialBypassed, JCheckBox showNotBypassed, JCheckBox showNA, PlaceholderTextField filterText,
			JCheckBox searchInPath, JCheckBox searchInRequest, JCheckBox searchInResponse, JCheckBox negativeSearch,
			MethodFilterDropDown_littlespidy methodFilterDropDown) {
		this(centerPanel, tableModel, showOnlyMarked, showDuplicates, showBypassed, showPotentialBypassed, showNotBypassed, showNA, filterText,
				searchInPath, searchInRequest, searchInResponse, negativeSearch, methodFilterDropDown, null);
	}

	public CustomRowSorter(CenterPanel centerPanel, RequestTableModel tableModel, JCheckBox showOnlyMarked, JCheckBox showDuplicates, JCheckBox showBypassed, 
			JCheckBox showPotentialBypassed, JCheckBox showNotBypassed, JCheckBox showNA, PlaceholderTextField filterText,
			JCheckBox searchInPath, JCheckBox searchInRequest, JCheckBox searchInResponse, JCheckBox negativeSearch,
			MethodFilterDropDown_littlespidy methodFilterDropDown,
			DomainFilterDropDown_littlespidy domainFilterDropDown) {
		super(tableModel);
		if (methodFilterDropDown != null) {
			methodFilterDropDown.addFilterChangeListener(() -> tableModel.fireTableDataChanged());
		}
		if (domainFilterDropDown != null) {
			domainFilterDropDown.addFilterChangeListener(() -> tableModel.fireTableDataChanged());
		}
		showOnlyMarked.addActionListener(e -> tableModel.fireTableDataChanged());
		showDuplicates.addActionListener(e -> tableModel.fireTableDataChanged());
		showBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showPotentialBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNotBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNA.addActionListener(e -> tableModel.fireTableDataChanged());
		filterText.addActionListener(e -> tableModel.fireTableDataChanged());
		setMaxSortKeys(1);
        setSortKeys(Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
		
		
		RowFilter<Object, Object> filter = new RowFilter<Object, Object>() {
			
			public boolean include(Entry<?, ?> entry) {
				if (methodFilterDropDown != null) {
					String method = entry.getStringValue(1);
					if (!methodFilterDropDown.isMethodSelected(method)) {
						return false;
					}
				}
				if (domainFilterDropDown != null) {
					String host = entry.getStringValue(2);
					if (!domainFilterDropDown.isDomainSelected(host)) {
						return false;
					}
				}
				if(filterText.getText() != null && !filterText.getText().equals("")) {
					centerPanel.toggleSearchButtonText();
					boolean doShow = false;
					if(searchInPath.isSelected()) {
						boolean contained = entry.getStringValue(3).toString().contains(filterText.getText());
						if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
							doShow = true;
						}
					}
					if(searchInRequest.isSelected() && !doShow) {	
						try {
							int id = Integer.parseInt(entry.getStringValue(0));
							List<Session> sessions = (tableModel instanceof ImportRequestTableModel_littlespidy) ?
								((ImportRequestTableModel_littlespidy) tableModel).getSessions() :
								CurrentConfig.getCurrentConfig().getSessions();
							for (Session session : sessions) {
								AnalyzerRequestResponse analyzerRequestResponse = session.getRequestResponseMap().get(id);
								if(analyzerRequestResponse != null && analyzerRequestResponse.getRequestResponse() != null && analyzerRequestResponse.getRequestResponse().getRequest() != null) {
									String response = new String(analyzerRequestResponse.getRequestResponse().getRequest());
									boolean contained = response.contains(filterText.getText());
									if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
										doShow = true;
										break;
									}
								}
							}
						}
						catch (Exception e) {
							e.printStackTrace();
						}
					}
					if(searchInResponse.isSelected() && !doShow) {	
						try {
							int id = Integer.parseInt(entry.getStringValue(0));
							List<Session> sessions = (tableModel instanceof ImportRequestTableModel_littlespidy) ?
								((ImportRequestTableModel_littlespidy) tableModel).getSessions() :
								CurrentConfig.getCurrentConfig().getSessions();
							for (Session session : sessions) {
								AnalyzerRequestResponse analyzerRequestResponse = session.getRequestResponseMap().get(id);
								if(analyzerRequestResponse != null && analyzerRequestResponse.getRequestResponse() != null && analyzerRequestResponse.getRequestResponse().getResponse() != null) {
									String response = new String(analyzerRequestResponse.getRequestResponse().getResponse());
									boolean contained = response.contains(filterText.getText());
									if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
										doShow = true;
										break;
									}
								}
							}
						}
						catch (Exception e) {
							e.printStackTrace();
						}
					}
					centerPanel.toggleSearchButtonText();
					if(!doShow && (searchInPath.isSelected() || searchInResponse.isSelected() || searchInRequest.isSelected())) {
						return false;
					}
				}
				if(showOnlyMarked.isSelected()) {
					OriginalRequestResponse requestResponse = tableModel.getOriginalRequestResponseById(Integer.parseInt(entry.getStringValue(0)));
					if(requestResponse != null && !requestResponse.isMarked()) {
						return false;
					}
				}
				if(!showDuplicates.isSelected()) {
					String endpoint = entry.getStringValue(1).toString() + entry.getStringValue(2).toString() 
							+ entry.getStringValue(3).toString();	
					if(tableModel.isDuplicate(Integer.parseInt(entry.getStringValue(0)), endpoint)) {
						return false;
					}
				}
				if(showBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SAME.toString())) {
							return true;
						}
					}
				}
				if(showPotentialBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SIMILAR.toString())) {
							return true;
						}
					}
				}
				if(showNotBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.DIFFERENT.toString())) {
							return true;
						}
					}
				}
				if(showNA.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.NA.toString())) {
							return true;
						}
					}
				}
				return false;
			}
		};
		
		setRowFilter(filter);
	}
}
