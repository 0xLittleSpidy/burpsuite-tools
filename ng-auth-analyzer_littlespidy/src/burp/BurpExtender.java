// Created with the help of an AI Agent and littlespidy.
package burp;

import java.awt.Component;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.protect7.authanalyzer.controller.HttpListener;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.util.DataStorageProvider;
import com.protect7.authanalyzer.util.Globals;

public class BurpExtender implements BurpExtension, IBurpExtender, ITab, IExtensionStateListener {

	public static MainPanel mainPanel;
	public static IBurpExtenderCallbacks callbacks;
	public static MontoyaApi api;
	public static JTabbedPane burpTabbedPane = null;

	private static final AtomicBoolean initialized = new AtomicBoolean(false);
	private static final AtomicBoolean startupPromptShown = new AtomicBoolean(false);

	@Override
	public void initialize(MontoyaApi montoyaApi) {
		BurpExtender.api = montoyaApi;
		montoyaApi.extension().setName(Globals.EXTENSION_NAME);

		if (initialized.compareAndSet(false, true)) {
			if (mainPanel == null) {
				mainPanel = new MainPanel();
			}
			montoyaApi.userInterface().registerSuiteTab(Globals.EXTENSION_NAME, mainPanel);
			montoyaApi.extension().registerUnloadingHandler(this::extensionUnloaded);
			montoyaApi.logging().logToOutput(Globals.EXTENSION_NAME + " successfully started");
			montoyaApi.logging().logToOutput("Version " + Globals.VERSION);
			montoyaApi.logging().logToOutput("Enhanced by littlespidy");

			promptStartupOnce();
		}
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		BurpExtender.callbacks = callbacks;
		callbacks.setExtensionName(Globals.EXTENSION_NAME);

		HttpListener httpListener = new HttpListener();
		callbacks.registerHttpListener(httpListener);
		callbacks.registerProxyListener(httpListener);
		callbacks.registerExtensionStateListener(this);

		if (initialized.compareAndSet(false, true)) {
			if (mainPanel == null) {
				mainPanel = new MainPanel();
			}
			callbacks.addSuiteTab(this);
			callbacks.printOutput(Globals.EXTENSION_NAME + " successfully started");
			callbacks.printOutput("Version " + Globals.VERSION);
			callbacks.printOutput("Enhanced by littlespidy");

			promptStartupOnce();
		}
	}

	private void promptStartupOnce() {
		if (startupPromptShown.compareAndSet(false, true)) {
			SwingUtilities.invokeLater(() -> {
				if (mainPanel != null && mainPanel.getPersistenceManager() != null) {
					mainPanel.getPersistenceManager().promptSessionStartup(mainPanel);
				}
			});
		}
	}

	@Override
	public String getTabCaption() {
		return Globals.EXTENSION_NAME;
	}

	@Override
	public Component getUiComponent() {
		return mainPanel;
	}

	@Override
	public void extensionUnloaded() {
		if (mainPanel != null && mainPanel.getPersistenceManager() != null) {
			try {
				mainPanel.getPersistenceManager().shutdown();
			} catch (Exception ignored) {}
		}
		try {
			if (mainPanel != null && mainPanel.getConfigurationPanel() != null) {
				mainPanel.getConfigurationPanel().createSessionObjects(false);
				DataStorageProvider.saveSetup();
			}
		} catch (Exception e) {
			if (callbacks != null) {
				callbacks.printOutput("INFO: Session Setup not stored due to invalid data.");
			}
		}
	}
}
