// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class CompleteUrlFilter_littlespidy extends RequestFilter {

	public CompleteUrlFilter_littlespidy(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if (onOffButton != null && onOffButton.isSelected() && requestInfo.getUrl() != null) {
			String url = requestInfo.getUrl().toString().trim().toLowerCase();
			for (String stringLiteral : stringLiterals) {
				String target = stringLiteral.trim().toLowerCase();
				if (!target.isEmpty() && (url.equals(target) || url.startsWith(target))) {
					incrementFiltered();
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}
}
