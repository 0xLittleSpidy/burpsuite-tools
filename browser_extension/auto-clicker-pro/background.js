// background.js

// Manage state per tab
const sessionStates = {};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = message.tabId || (sender.tab ? sender.tab.id : null);
  if (!tabId) {
    sendResponse({ error: 'No tab ID provided' });
    return true;
  }

  // Initialize state if not exists
  if (!sessionStates[tabId]) {
    sessionStates[tabId] = {
      state: 'stopped', // running, paused, stopped
      stats: {
        totalFound: 0,
        clicked: 0,
        errors: 0,
        startTime: null,
        elapsed: 0
      }
    };
  }

  switch (message.action) {
    case 'getState':
      sendResponse(sessionStates[tabId]);
      break;

    case 'start':
      sessionStates[tabId].state = 'running';
      sessionStates[tabId].stats.startTime = Date.now();
      sendMessageToTab(tabId, { action: 'start_clicking' });
      sendResponse({ status: 'started' });
      break;

    case 'pause':
      sessionStates[tabId].state = 'paused';
      sendMessageToTab(tabId, { action: 'pause_clicking' });
      sendResponse({ status: 'paused' });
      break;

    case 'resume':
      sessionStates[tabId].state = 'running';
      sendMessageToTab(tabId, { action: 'resume_clicking' });
      sendResponse({ status: 'resumed' });
      break;

    case 'stop':
      sessionStates[tabId].state = 'stopped';
      if (sessionStates[tabId].stats.startTime) {
        sessionStates[tabId].stats.elapsed += Date.now() - sessionStates[tabId].stats.startTime;
      }
      saveSessionHistory(tabId, sessionStates[tabId].stats);
      sendMessageToTab(tabId, { action: 'stop_clicking' });
      sendResponse({ status: 'stopped' });
      break;

    case 'updateStats':
      // From content script
      if (message.stats) {
        Object.assign(sessionStates[tabId].stats, message.stats);
      }
      sendResponse({ status: 'stats_updated' });
      break;

    default:
      sendResponse({ error: 'Unknown action' });
  }

  return true; // Keep message channel open for async response
});

function sendMessageToTab(tabId, message) {
  chrome.tabs.sendMessage(tabId, message, (response) => {
    if (chrome.runtime.lastError) {
      console.error(`Error sending message to tab ${tabId}:`, chrome.runtime.lastError.message);
    }
  });
}

function saveSessionHistory(tabId, stats) {
  chrome.storage.local.get(['sessionHistory'], (result) => {
    const history = result.sessionHistory || [];
    history.push({
      tabId: tabId,
      date: new Date().toISOString(),
      stats: stats
    });
    chrome.storage.local.set({ sessionHistory: history }, () => {
      if (chrome.runtime.lastError) {
        console.error('Error saving session history:', chrome.runtime.lastError.message);
      }
    });
  });
}

// Clean up state when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  if (sessionStates[tabId]) {
    delete sessionStates[tabId];
  }
});
