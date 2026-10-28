// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.persistence;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SessionStateDTO_littlespidy {

	public String version;
	public long timestamp;
	public String configSetupJson;
	public String tableSettings;
	public List<MessageEntryDTO> liveMessages = new ArrayList<MessageEntryDTO>();
	public List<String> importedSessionNames = new ArrayList<String>();
	public List<MessageEntryDTO> importedMessages = new ArrayList<MessageEntryDTO>();
	public List<ConvertResultEntryDTO> convertResults = new ArrayList<ConvertResultEntryDTO>();
	public List<CorsResultEntryDTO> corsResults = new ArrayList<CorsResultEntryDTO>();

	public static class CorsResultEntryDTO {
		public int id;
		public String method;
		public String host;
		public String path;
		public String testedOrigin;
		public String testTypeDescription;
		public String reflectedAcao;
		public boolean acacPresent;
		public int statusCode;
		public int length;
		public String severity;
		public String requestBase64;
		public String responseBase64;
	}

	public static class ConvertResultEntryDTO {
		public int id;
		public String method;
		public String host;
		public String path;
		public int postStatus;
		public int getStatus;
		public int postLength;
		public int getLength;
		public String contentType;
		public String signal;
		public String severity;
		public String evidence;
		public String originalRequestBase64;
		public String originalResponseBase64;
		public String convertedRequestBase64;
		public String convertedResponseBase64;
	}

	public static class MessageEntryDTO {
		public int id;
		public String method;
		public String host;
		public String url;
		public String comment;
		public boolean marked;
		public int statusCode;
		public int responseContentLength;
		public String requestBase64;
		public String responseBase64;
		public Map<String, SessionMessageDTO> sessionData = new HashMap<String, SessionMessageDTO>();
	}

	public static class SessionMessageDTO {
		public String status;
		public int statusCode;
		public int responseContentLength;
		public String infoText;
		public String requestBase64;
		public String responseBase64;
	}
}
