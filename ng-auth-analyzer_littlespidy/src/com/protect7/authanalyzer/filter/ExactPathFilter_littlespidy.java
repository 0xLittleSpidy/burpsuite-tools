// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class ExactPathFilter_littlespidy extends RequestFilter {

	public ExactPathFilter_littlespidy(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if (onOffButton != null && onOffButton.isSelected() && requestInfo.getUrl() != null && requestInfo.getUrl().getPath() != null) {
			String path = requestInfo.getUrl().getPath().trim().toLowerCase();
			for (String stringLiteral : stringLiterals) {
				String target = stringLiteral.trim().toLowerCase();
				if (!target.isEmpty() && path.equals(target)) {
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
