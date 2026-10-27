// Created with the help of an AI Agent and littlespidy.
package com.protect7.authanalyzer.persistence;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.CustomHttpRequestResponse_littlespidy;
import com.protect7.authanalyzer.entities.CustomHttpService_littlespidy;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.DataStorageProvider;
import com.protect7.authanalyzer.util.Globals;

public class PersistenceManager_littlespidy {

	private final MontoyaApi api;
	private final IBurpExtenderCallbacks callbacks;
	private final Gson gson;
	private volatile File activeSessionFile = null;
	private final JLabel sessionStatusLabel;
	private MainPanel mainPanel;

	private final ScheduledExecutorService autoSaveExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
		Thread t = new Thread(r, "ng-auth-analyzer-autosave");
		t.setDaemon(true);
		return t;
	});
	private ScheduledFuture<?> pendingSaveTask;
	private final Object saveLock = new Object();

	public PersistenceManager_littlespidy(MontoyaApi api, IBurpExtenderCallbacks callbacks) {
		this.api = api;
		this.callbacks = callbacks;
		this.gson = new GsonBuilder().setPrettyPrinting().create();
		this.sessionStatusLabel = new JLabel("Session: [Temporary / In-Memory]");
		this.sessionStatusLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
	}

	public void setMainPanel(MainPanel mainPanel) {
		this.mainPanel = mainPanel;
	}

	public File getActiveSessionFile() {
		return activeSessionFile;
	}

	public void setActiveSessionFile(File file) {
		this.activeSessionFile = file;
		updateStatusLabel();
	}

	public JPanel createToolbar() {
		JPanel toolbar = new JPanel(new BorderLayout(10, 0));
		toolbar.setBorder(new EmptyBorder(4, 6, 4, 6));

		JPanel leftButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
		JButton newBtn = new JButton("New Session");
		newBtn.setToolTipText("Create a new session and bind to a destination file");
		newBtn.addActionListener(e -> promptNewSession());

		JButton openBtn = new JButton("Open Session");
		openBtn.setToolTipText("Open an existing session JSON file");
		openBtn.addActionListener(e -> promptOpenSession());

		JButton saveBtn = new JButton("Save Session");
		saveBtn.setToolTipText("Save current state to bound session file");
		saveBtn.addActionListener(e -> {
			if (activeSessionFile != null) {
				saveSync();
				JOptionPane.showMessageDialog(mainPanel, "Session saved successfully to:\n" + activeSessionFile.getAbsolutePath());
			} else {
				promptSaveAsSession();
			}
		});

		JButton saveAsBtn = new JButton("Save As...");
		saveAsBtn.setToolTipText("Save current state to a new session file");
		saveAsBtn.addActionListener(e -> promptSaveAsSession());

		JButton offboardBtn = new JButton("Offboard Session");
		offboardBtn.setToolTipText("Unbind active session file and clear workspace to clean fresh state");
		offboardBtn.addActionListener(e -> offboardSession());

		leftButtons.add(newBtn);
		leftButtons.add(openBtn);
		leftButtons.add(saveBtn);
		leftButtons.add(saveAsBtn);
		leftButtons.add(offboardBtn);

		JPanel rightStatus = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
		rightStatus.add(sessionStatusLabel);

		toolbar.add(leftButtons, BorderLayout.WEST);
		toolbar.add(rightStatus, BorderLayout.EAST);
		return toolbar;
	}

	public void updateStatusLabel() {
		SwingUtilities.invokeLater(() -> {
			if (activeSessionFile != null) {
				sessionStatusLabel.setText("Session: " + activeSessionFile.getName() + " (" + activeSessionFile.getParent() + ")");
				sessionStatusLabel.setForeground(new Color(0, 120, 0));
			} else {
				sessionStatusLabel.setText("Session: [Temporary / In-Memory]");
				sessionStatusLabel.setForeground(Color.DARK_GRAY);
			}
		});
	}

	public synchronized void triggerAutoSave() {
		if (activeSessionFile == null) {
			return;
		}
		if (pendingSaveTask != null && !pendingSaveTask.isDone()) {
			pendingSaveTask.cancel(false);
		}
		pendingSaveTask = autoSaveExecutor.schedule(this::saveSync, 1500, TimeUnit.MILLISECONDS);
	}

	public void saveSync() {
		if (activeSessionFile == null || mainPanel == null) {
			return;
		}
		synchronized (saveLock) {
			try {
				SessionStateDTO_littlespidy dto = new SessionStateDTO_littlespidy();
				dto.version = Globals.VERSION;
				dto.timestamp = System.currentTimeMillis();

				try {
					mainPanel.getConfigurationPanel().createSessionObjects(false);
					dto.configSetupJson = DataStorageProvider.getSetupAsJsonString();
				} catch (Exception ignored) {}

				if (callbacks != null) {
					try {
						dto.tableSettings = callbacks.loadExtensionSetting("TABLE_SETTINGS");
					} catch (Exception ignored) {}
				}

				// Live messages
				if (mainPanel.getHistoryPanel() != null && mainPanel.getHistoryPanel().getTableModel() != null) {
					for (OriginalRequestResponse orig : mainPanel.getHistoryPanel().getTableModel().getOriginalRequestResponseList()) {
						SessionStateDTO_littlespidy.MessageEntryDTO msgDto = buildMessageEntryDTO(orig, CurrentConfig.getCurrentConfig().getSessions());
						dto.liveMessages.add(msgDto);
					}
				}

				// Imported messages
				if (mainPanel.getImportPanel() != null) {
					for (Session s : mainPanel.getImportPanel().getImportedSessions()) {
						dto.importedSessionNames.add(s.getName());
					}
					for (OriginalRequestResponse orig : mainPanel.getImportPanel().getImportTableModel().getOriginalRequestResponseList()) {
						SessionStateDTO_littlespidy.MessageEntryDTO msgDto = buildMessageEntryDTO(orig, mainPanel.getImportPanel().getImportedSessions());
						dto.importedMessages.add(msgDto);
					}
				}

				// Convert POST to GET results
				if (mainPanel.getConvertPanel() != null && mainPanel.getConvertPanel().getConversionTableModel() != null) {
					for (com.protect7.authanalyzer.convert.ConversionResult_littlespidy cr : mainPanel.getConvertPanel().getConversionTableModel().getAllResults()) {
						SessionStateDTO_littlespidy.ConvertResultEntryDTO crDto = new SessionStateDTO_littlespidy.ConvertResultEntryDTO();
						crDto.id = cr.getId();
						crDto.method = cr.getMethod();
						crDto.host = cr.getHost();
						crDto.path = cr.getPath();
						crDto.postStatus = cr.getPostStatus();
						crDto.getStatus = cr.getGetStatus();
						crDto.postLength = cr.getPostLength();
						crDto.getLength = cr.getGetLength();
						crDto.contentType = cr.getContentType();
						crDto.signal = cr.getSignal();
						crDto.severity = cr.getSeverity();
						crDto.evidence = cr.getEvidence();
						if (cr.getOriginalRequestResponse() != null) {
							if (cr.getOriginalRequestResponse().getRequest() != null) {
								crDto.originalRequestBase64 = Base64.getEncoder().encodeToString(cr.getOriginalRequestResponse().getRequest());
							}
							if (cr.getOriginalRequestResponse().getResponse() != null) {
								crDto.originalResponseBase64 = Base64.getEncoder().encodeToString(cr.getOriginalRequestResponse().getResponse());
							}
						}
						if (cr.getConvertedRequestResponse() != null) {
							if (cr.getConvertedRequestResponse().getRequest() != null) {
								crDto.convertedRequestBase64 = Base64.getEncoder().encodeToString(cr.getConvertedRequestResponse().getRequest());
							}
							if (cr.getConvertedRequestResponse().getResponse() != null) {
								crDto.convertedResponseBase64 = Base64.getEncoder().encodeToString(cr.getConvertedRequestResponse().getResponse());
							}
						}
						dto.convertResults.add(crDto);
					}
				}

				String json = gson.toJson(dto);
				File tmpFile = new File(activeSessionFile.getAbsolutePath() + ".tmp");
				Files.writeString(tmpFile.toPath(), json, StandardCharsets.UTF_8);
				Files.move(tmpFile.toPath(), activeSessionFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
			} catch (Exception e) {
				if (callbacks != null) {
					callbacks.printError("Error saving session file: " + e.getMessage());
				}
			}
		}
	}

	private SessionStateDTO_littlespidy.MessageEntryDTO buildMessageEntryDTO(OriginalRequestResponse orig, List<Session> sessions) {
		SessionStateDTO_littlespidy.MessageEntryDTO msgDto = new SessionStateDTO_littlespidy.MessageEntryDTO();
		msgDto.id = orig.getId();
		msgDto.method = orig.getMethod();
		msgDto.host = orig.getHost();
		msgDto.url = orig.getUrl();
		msgDto.comment = orig.getComment();
		msgDto.marked = orig.isMarked();
		msgDto.statusCode = orig.getStatusCode();
		msgDto.responseContentLength = orig.getResponseContentLength();

		if (orig.getRequestResponse() != null) {
			if (orig.getRequestResponse().getRequest() != null) {
				msgDto.requestBase64 = Base64.getEncoder().encodeToString(orig.getRequestResponse().getRequest());
			}
			if (orig.getRequestResponse().getResponse() != null) {
				msgDto.responseBase64 = Base64.getEncoder().encodeToString(orig.getRequestResponse().getResponse());
			}
		}

		if (sessions != null) {
			for (Session s : sessions) {
				AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orig.getId());
				if (arr != null) {
					SessionStateDTO_littlespidy.SessionMessageDTO smDto = new SessionStateDTO_littlespidy.SessionMessageDTO();
					smDto.status = arr.getStatus() != null ? arr.getStatus().getName() : "";
					smDto.statusCode = arr.getStatusCode();
					smDto.responseContentLength = arr.getResponseContentLength();
					smDto.infoText = arr.getInfoText();
					if (arr.getRequestResponse() != null) {
						if (arr.getRequestResponse().getRequest() != null) {
							smDto.requestBase64 = Base64.getEncoder().encodeToString(arr.getRequestResponse().getRequest());
						}
						if (arr.getRequestResponse().getResponse() != null) {
							smDto.responseBase64 = Base64.getEncoder().encodeToString(arr.getRequestResponse().getResponse());
						}
					}
					msgDto.sessionData.put(s.getName(), smDto);
				}
			}
		}
		return msgDto;
	}

	public void promptNewSession() {
		File lastDir = SessionStartupDialog_littlespidy.getLastDirectory(api, callbacks);
		JFileChooser chooser = new JFileChooser(lastDir);
		chooser.setDialogTitle("Select Directory to Save New Session");
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		int res = chooser.showOpenDialog(mainPanel);
		if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
			File dir = chooser.getSelectedFile();
			SessionStartupDialog_littlespidy.rememberDirectory(api, callbacks, dir.getAbsolutePath());
			String fileName = JOptionPane.showInputDialog(mainPanel, "Enter session filename:", "auth_analyzer_session.json");
			if (fileName != null && !fileName.trim().isEmpty()) {
				if (!fileName.toLowerCase().endsWith(".json")) {
					fileName = fileName.trim() + ".json";
				}
				File sessionFile = new File(dir, fileName.trim());
				this.activeSessionFile = sessionFile;
				updateStatusLabel();
				saveSync();
				JOptionPane.showMessageDialog(mainPanel, "New session created and bound to:\n" + sessionFile.getAbsolutePath());
			}
		}
	}

	public void promptOpenSession() {
		File lastDir = SessionStartupDialog_littlespidy.getLastDirectory(api, callbacks);
		JFileChooser chooser = new JFileChooser(lastDir);
		chooser.setDialogTitle("Open Session File");
		chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
		int res = chooser.showOpenDialog(mainPanel);
		if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
			File file = chooser.getSelectedFile();
			SessionStartupDialog_littlespidy.rememberDirectory(api, callbacks, file.getParent());
			loadSession(file);
		}
	}

	public void promptSaveAsSession() {
		File lastDir = SessionStartupDialog_littlespidy.getLastDirectory(api, callbacks);
		JFileChooser chooser = new JFileChooser(lastDir);
		chooser.setDialogTitle("Save Session As");
		chooser.setFileFilter(new FileNameExtensionFilter("JSON Session Files (*.json)", "json"));
		int res = chooser.showSaveDialog(mainPanel);
		if (res == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
			File file = chooser.getSelectedFile();
			if (!file.getName().toLowerCase().endsWith(".json")) {
				file = new File(file.getParentFile(), file.getName() + ".json");
			}
			SessionStartupDialog_littlespidy.rememberDirectory(api, callbacks, file.getParent());
			this.activeSessionFile = file;
			updateStatusLabel();
			saveSync();
			JOptionPane.showMessageDialog(mainPanel, "Session saved as:\n" + file.getAbsolutePath());
		}
	}

	public void loadSession(File file) {
		synchronized (saveLock) {
			try {
				if (!file.exists()) {
					JOptionPane.showMessageDialog(mainPanel, "Session file not found: " + file.getAbsolutePath(), "Error", JOptionPane.ERROR_MESSAGE);
					return;
				}
				String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);
				SessionStateDTO_littlespidy dto = gson.fromJson(json, SessionStateDTO_littlespidy.class);
				if (dto == null) {
					JOptionPane.showMessageDialog(mainPanel, "Invalid session JSON in file.", "Error", JOptionPane.ERROR_MESSAGE);
					return;
				}

				// 1. Restore configuration setup
				if (dto.configSetupJson != null && !dto.configSetupJson.isBlank()) {
					try {
						mainPanel.getConfigurationPanel().loadSetup(dto.configSetupJson);
					} catch (Exception ex) {
						if (callbacks != null) callbacks.printError("Error loading config setup: " + ex.getMessage());
					}
				}

				// 2. Restore live history
				if (mainPanel.getHistoryPanel() != null) {
					mainPanel.getHistoryPanel().clearTable();
					List<Session> configSessions = CurrentConfig.getCurrentConfig().getSessions();
					for (SessionStateDTO_littlespidy.MessageEntryDTO msgDto : dto.liveMessages) {
						OriginalRequestResponse orig = reconstructOriginal(msgDto);
						mainPanel.getHistoryPanel().getTableModel().addNewRequestResponse(orig);
						for (Session s : configSessions) {
							SessionStateDTO_littlespidy.SessionMessageDTO smDto = msgDto.sessionData.get(s.getName());
							if (smDto != null) {
								AnalyzerRequestResponse arr = reconstructAnalyzer(smDto, orig.getHost());
								s.getRequestResponseMap().put(orig.getId(), arr);
							}
						}
					}
				}

				// 3. Restore imported history
				if (mainPanel.getImportPanel() != null && dto.importedMessages != null && !dto.importedMessages.isEmpty()) {
					List<Session> impSessions = new ArrayList<Session>();
					for (String sName : dto.importedSessionNames) {
						impSessions.add(new Session(sName));
					}
					List<OriginalRequestResponse> impOrigs = new ArrayList<OriginalRequestResponse>();
					for (SessionStateDTO_littlespidy.MessageEntryDTO msgDto : dto.importedMessages) {
						OriginalRequestResponse orig = reconstructOriginal(msgDto);
						impOrigs.add(orig);
						for (Session s : impSessions) {
							SessionStateDTO_littlespidy.SessionMessageDTO smDto = msgDto.sessionData.get(s.getName());
							if (smDto != null) {
								AnalyzerRequestResponse arr = reconstructAnalyzer(smDto, orig.getHost());
								s.getRequestResponseMap().put(orig.getId(), arr);
							}
						}
					}
					mainPanel.getImportPanel().setImportedData(impOrigs, impSessions);
				}

				// 4. Restore Convert POST to GET results
				if (mainPanel.getConvertPanel() != null && dto.convertResults != null) {
					mainPanel.getConvertPanel().clearLiveConversions();
					List<com.protect7.authanalyzer.convert.ConversionResult_littlespidy> restoredResults = new ArrayList<>();
					for (SessionStateDTO_littlespidy.ConvertResultEntryDTO crDto : dto.convertResults) {
						byte[] origReq = decodeBase64Safe(crDto.originalRequestBase64);
						byte[] origResp = decodeBase64Safe(crDto.originalResponseBase64);
						CustomHttpService_littlespidy origService = new CustomHttpService_littlespidy(crDto.host, 443, "https");
						CustomHttpRequestResponse_littlespidy origReqResp = new CustomHttpRequestResponse_littlespidy(origReq, origResp, origService);

						byte[] convReq = decodeBase64Safe(crDto.convertedRequestBase64);
						byte[] convResp = decodeBase64Safe(crDto.convertedResponseBase64);
						CustomHttpService_littlespidy convService = new CustomHttpService_littlespidy(crDto.host, 443, "https");
						CustomHttpRequestResponse_littlespidy convReqResp = new CustomHttpRequestResponse_littlespidy(convReq, convResp, convService);

						com.protect7.authanalyzer.convert.ConversionResult_littlespidy res = new com.protect7.authanalyzer.convert.ConversionResult_littlespidy(
								crDto.id, crDto.method, crDto.host, crDto.path,
								crDto.postStatus, crDto.getStatus, crDto.postLength, crDto.getLength,
								crDto.contentType, crDto.signal, crDto.severity, crDto.evidence,
								origReqResp, convReqResp);
						restoredResults.add(res);
					}
					mainPanel.getConvertPanel().getConversionTableModel().addResults(restoredResults);
				}

				this.activeSessionFile = file;
				updateStatusLabel();
				JOptionPane.showMessageDialog(mainPanel, "Session loaded successfully from:\n" + file.getAbsolutePath());
			} catch (Exception e) {
				JOptionPane.showMessageDialog(mainPanel, "Failed to load session: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	private OriginalRequestResponse reconstructOriginal(SessionStateDTO_littlespidy.MessageEntryDTO dto) {
		byte[] req = decodeBase64Safe(dto.requestBase64);
		byte[] resp = decodeBase64Safe(dto.responseBase64);
		CustomHttpService_littlespidy service = new CustomHttpService_littlespidy(dto.host, 443, "https");
		CustomHttpRequestResponse_littlespidy reqResp = new CustomHttpRequestResponse_littlespidy(req, resp, service);
		reqResp.setComment(dto.comment);
		OriginalRequestResponse orig = new OriginalRequestResponse(dto.id, reqResp, dto.method, dto.url, "", dto.statusCode, dto.responseContentLength);
		orig.setComment(dto.comment);
		orig.setMarked(dto.marked);
		return orig;
	}

	private AnalyzerRequestResponse reconstructAnalyzer(SessionStateDTO_littlespidy.SessionMessageDTO dto, String host) {
		byte[] req = decodeBase64Safe(dto.requestBase64);
		byte[] resp = decodeBase64Safe(dto.responseBase64);
		CustomHttpService_littlespidy service = new CustomHttpService_littlespidy(host, 443, "https");
		CustomHttpRequestResponse_littlespidy reqResp = new CustomHttpRequestResponse_littlespidy(req, resp, service);
		BypassConstants bc = BypassConstants.NA;
		if (dto.status != null) {
			for (BypassConstants c : BypassConstants.values()) {
				if (c.getName().equalsIgnoreCase(dto.status)) {
					bc = c;
					break;
				}
			}
		}
		return new AnalyzerRequestResponse(reqResp, bc, dto.infoText, dto.statusCode, dto.responseContentLength);
	}

	private byte[] decodeBase64Safe(String base64) {
		if (base64 != null && !base64.isBlank()) {
			try {
				return Base64.getDecoder().decode(base64.trim());
			} catch (Exception ignored) {}
		}
		return new byte[0];
	}

	public void offboardSession() {
		if (activeSessionFile != null) {
			int opt = JOptionPane.showConfirmDialog(mainPanel,
					"Do you want to save changes to the current session before offboarding?",
					"Offboard Session",
					JOptionPane.YES_NO_CANCEL_OPTION);
			if (opt == JOptionPane.CANCEL_OPTION) {
				return;
			}
			if (opt == JOptionPane.YES_OPTION) {
				saveSync();
			}
		}
		this.activeSessionFile = null;
		if (mainPanel.getHistoryPanel() != null) {
			mainPanel.getHistoryPanel().clearTable();
		}
		if (mainPanel.getImportPanel() != null) {
			mainPanel.getImportPanel().clearTable();
		}
		if (mainPanel.getConvertPanel() != null) {
			mainPanel.getConvertPanel().clearLiveConversions();
			mainPanel.getConvertPanel().clearDiscovery();
		}
		updateStatusLabel();
		JOptionPane.showMessageDialog(mainPanel, "Session offboarded. Workspace restored to clean state.");
	}

	public void promptSessionStartup(Component parent) {
		SessionStartupDialog_littlespidy.StartupResult res = SessionStartupDialog_littlespidy.promptUser(api, callbacks, parent);
		if (res.getAction() == SessionStartupDialog_littlespidy.StartupAction.OPEN_EXISTING && res.getSessionFile() != null) {
			loadSession(res.getSessionFile());
		} else if (res.getAction() == SessionStartupDialog_littlespidy.StartupAction.CREATE_NEW && res.getSessionFile() != null) {
			this.activeSessionFile = res.getSessionFile();
			updateStatusLabel();
			saveSync();
		} else {
			this.activeSessionFile = null;
			updateStatusLabel();
		}
	}

	public void shutdown() {
		if (activeSessionFile != null) {
			saveSync();
		}
		autoSaveExecutor.shutdown();
		try {
			if (!autoSaveExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
				autoSaveExecutor.shutdownNow();
			}
		} catch (InterruptedException e) {
			autoSaveExecutor.shutdownNow();
			Thread.currentThread().interrupt();
		}
	}
}
