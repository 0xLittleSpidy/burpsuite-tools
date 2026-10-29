package com.protect7.authanalyzer.controller;

import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.gui.cors.CorsHistoryPanel_littlespidy;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class HttpListener implements IHttpListener, IProxyListener {

	private final CurrentConfig config = CurrentConfig.getCurrentConfig();

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		boolean authActive = BurpExtender.mainPanel == null || BurpExtender.mainPanel.getConfigurationPanel() == null ||
				BurpExtender.mainPanel.getConfigurationPanel().isAuthAnalyzerActive();
		if(config.isRunning() && authActive && (!messageIsRequest || (messageIsRequest && config.isDropOriginal() && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY))) {		
			if(!isFiltered(toolFlag, messageInfo)) {
				config.performAuthAnalyzerRequest(messageInfo);
			}
		}

		if (!messageIsRequest && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
			if (BurpExtender.mainPanel != null && BurpExtender.mainPanel.getConfigurationPanel() != null &&
					BurpExtender.mainPanel.getConfigurationPanel().isCorsTestingActive()) {
				if (!isFiltered(toolFlag, messageInfo) && BurpExtender.mainPanel.getCorsHistoryPanel() != null) {
					BurpExtender.mainPanel.getCorsHistoryPanel().analyzeRequestAsync(messageInfo);
				}
			}
			if (BurpExtender.mainPanel != null && BurpExtender.mainPanel.getConfigurationPanel() != null &&
					BurpExtender.mainPanel.getConfigurationPanel().isConvertPostToGetActive()) {
				if (!isFiltered(toolFlag, messageInfo) && BurpExtender.mainPanel.getConvertPanel() != null) {
					IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
					if ("POST".equalsIgnoreCase(reqInfo.getMethod())) {
						BurpExtender.mainPanel.getConvertPanel().analyzePostRequestAsync(messageInfo);
					}
				}
			}
			if (BurpExtender.mainPanel != null && BurpExtender.mainPanel.getConfigurationPanel() != null &&
					BurpExtender.mainPanel.getConfigurationPanel().isInputValidationRunning()) {
				if (!isFiltered(toolFlag, messageInfo) && BurpExtender.mainPanel.getInputValidationPanel() != null) {
					IRequestInfo reqInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
					if (reqInfo.getParameters() != null && !reqInfo.getParameters().isEmpty()) {
						BurpExtender.mainPanel.getInputValidationPanel().analyzeRequestAsync(messageInfo);
					}
				}
			}
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		if(config.isDropOriginal() && messageIsRequest) {
			if(!isFiltered(IBurpExtenderCallbacks.TOOL_PROXY, message.getMessageInfo())) {
				processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, true, message.getMessageInfo());
				message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
			}
		}
	}
	
	private boolean isFiltered(int toolFlag, IHttpRequestResponse messageInfo) {
		boolean isFiltered = false;
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
		IResponseInfo responseInfo = null;
		if(messageInfo.getResponse() != null) {
			responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
		}
		for(int i=0; i<config.getRequestFilterList().size(); i++) {
			RequestFilter filter = config.getRequestFilterAt(i);
			if(filter.filterRequest(BurpExtender.callbacks, toolFlag, requestInfo, responseInfo)) {
				return true;
			}
		}
		return isFiltered;
	}
}
