// popup.js
let isRunning = false;
let isPaused = false;
let startTime = null;
let timerInterval = null;
let state = {
  status: 'stopped',
  stats: { found: 0, clicked: 0, skipped: 0, errors: 0 },
  elapsedTime: 0
};
let logs = [];

// DOM Elements
const els = {
  statusIndicator: document.getElementById('status-indicator'),
  statusText: document.getElementById('status-text'),
  timer: document.getElementById('timer'),
  statFound: document.getElementById('stat-found'),
  statClicked: document.getElementById('stat-clicked'),
  statSkipped: document.getElementById('stat-skipped'),
  statErrors: document.getElementById('stat-errors'),
  btnStart: document.getElementById('btn-start'),
  btnPause: document.getElementById('btn-pause'),
  btnStop: document.getElementById('btn-stop'),
  btnRescan: document.getElementById('btn-rescan'),
  btnExport: document.getElementById('btn-export'),
  delayInput: document.getElementById('click-delay'),
  delayVal: document.getElementById('delay-val'),
  activityLog: document.getElementById('activity-log')
};

// Collapsible logic
document.querySelectorAll('.collapsible-btn').forEach(btn => {
  btn.addEventListener('click', function() {
    this.classList.toggle('active');
    let content = this.nextElementSibling;
    if (content.style.maxHeight) {
      content.style.maxHeight = null;
    } else {
      content.style.maxHeight = content.scrollHeight + "px";
    }
  });
});

// Config logic
els.delayInput.addEventListener('input', (e) => {
  els.delayVal.textContent = e.target.value;
  saveConfig();
});

const configInputs = ['inc-links', 'inc-iframes', 'inc-shadow', 'prev-nav', 'max-depth', 'click-order', 'element-filter', 'exclude-selectors', 'max-clicks', 'skip-dangerous'];
configInputs.forEach(id => {
  document.getElementById(id).addEventListener('change', saveConfig);
});

function saveConfig() {
  const config = {
    clickDelay: parseInt(els.delayInput.value, 10),
    includeLinks: document.getElementById('inc-links').checked,
    includeIframes: document.getElementById('inc-iframes').checked,
    includeShadowDom: document.getElementById('inc-shadow').checked,
    preventNavigation: document.getElementById('prev-nav').checked,
    maxDepth: parseInt(document.getElementById('max-depth').value, 10),
    clickOrder: document.getElementById('click-order').value,
    elementFilter: document.getElementById('element-filter').value,
    excludeSelectors: document.getElementById('exclude-selectors').value,
    maxClicks: parseInt(document.getElementById('max-clicks').value, 10),
    skipDangerous: document.getElementById('skip-dangerous').checked
  };
  chrome.storage.local.set({ config });
  sendMessageToTab({ action: 'updateConfig', config });
}

function loadConfig() {
  chrome.storage.local.get(['config'], (result) => {
    if (result.config) {
      const c = result.config;
      els.delayInput.value = c.clickDelay || 1000;
      els.delayVal.textContent = c.clickDelay || 1000;
      document.getElementById('inc-links').checked = !!c.includeLinks;
      document.getElementById('inc-iframes').checked = !!c.includeIframes;
      document.getElementById('inc-shadow').checked = !!c.includeShadowDom;
      document.getElementById('prev-nav').checked = c.preventNavigation !== false;
      document.getElementById('max-depth').value = c.maxDepth || 5;
      document.getElementById('click-order').value = c.clickOrder || 'dom';
      document.getElementById('element-filter').value = c.elementFilter || '';
      document.getElementById('exclude-selectors').value = c.excludeSelectors || '';
      document.getElementById('max-clicks').value = c.maxClicks || 0;
      document.getElementById('skip-dangerous').checked = c.skipDangerous !== false;
    }
  });
}

// Controls
els.btnStart.addEventListener('click', () => {
  if (isPaused) {
    sendMessageToTab({ action: 'resume' });
  } else {
    chrome.storage.local.get(['config'], (result) => {
      sendMessageToTab({ action: 'start', config: result.config || {} });
    });
    startTime = Date.now() - state.elapsedTime;
    timerInterval = setInterval(updateTimer, 1000);
  }
});

els.btnPause.addEventListener('click', () => {
  sendMessageToTab({ action: 'pause' });
});

els.btnStop.addEventListener('click', () => {
  sendMessageToTab({ action: 'stop' });
  clearInterval(timerInterval);
  state.elapsedTime = 0;
});

els.btnRescan.addEventListener('click', () => {
  sendMessageToTab({ action: 'rescan' });
});

els.btnExport.addEventListener('click', () => {
  const report = {
    extension: 'AutoClicker Pro',
    exportDate: new Date().toISOString(),
    stats: state.stats,
    elapsedTime: formatTime(state.elapsedTime),
    logs: logs
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `autoclicker-report-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

function updateTimer() {
  if (!isPaused && state.status === 'running') {
    state.elapsedTime = Date.now() - startTime;
    els.timer.textContent = formatTime(state.elapsedTime);
  }
}

function formatTime(ms) {
  let seconds = Math.floor(ms / 1000);
  let minutes = Math.floor(seconds / 60);
  seconds = seconds % 60;
  return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
}

// Messaging
function sendMessageToTab(msg) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, msg);
    }
  });
}

function sendMessageToBackground(msg) {
  chrome.runtime.sendMessage(msg);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'STATE_UPDATE') {
    updateUI(msg.state);
  } else if (msg.type === 'LOG_ENTRY') {
    addLogEntry(msg.entry);
  }
});

function updateUI(newState) {
  state = { ...state, ...newState };
  
  els.statusText.textContent = state.status.charAt(0).toUpperCase() + state.status.slice(1);
  els.statusIndicator.className = 'status-indicator ' + state.status;
  
  els.statFound.textContent = state.stats.found || 0;
  els.statClicked.textContent = state.stats.clicked || 0;
  els.statSkipped.textContent = state.stats.skipped || 0;
  els.statErrors.textContent = state.stats.errors || 0;

  if (state.status === 'running' || state.status === 'scanning') {
    isRunning = true;
    isPaused = false;
    els.btnStart.classList.add('hidden');
    els.btnPause.classList.remove('hidden');
    if (!startTime) {
      startTime = Date.now() - (state.elapsedTime || 0);
      timerInterval = setInterval(updateTimer, 1000);
    }
  } else if (state.status === 'paused') {
    isRunning = false;
    isPaused = true;
    els.btnStart.classList.remove('hidden');
    els.btnPause.classList.add('hidden');
    els.btnStart.innerHTML = '▶️ Resume';
    clearInterval(timerInterval);
  } else {
    isRunning = false;
    isPaused = false;
    els.btnStart.classList.remove('hidden');
    els.btnPause.classList.add('hidden');
    els.btnStart.innerHTML = '▶️ Start';
    clearInterval(timerInterval);
    startTime = null;
    els.timer.textContent = formatTime(state.elapsedTime || 0);
  }
}

function addLogEntry(entry) {
  logs.push(entry);
  if (logs.length > 100) logs.shift();
  
  const div = document.createElement('div');
  div.className = 'log-entry';
  
  const time = new Date(entry.timestamp).toLocaleTimeString([], {hour12: false});
  const icons = { info: 'ℹ️', click: '✅', skip: '⏭️', error: '❌', scan: '🔍' };
  const icon = icons[entry.type] || 'ℹ️';
  
  div.innerHTML = `<span class="log-time">[${time}]</span><span class="log-icon">${icon}</span> ${entry.message}`;
  
  els.activityLog.appendChild(div);
  els.activityLog.scrollTop = els.activityLog.scrollHeight;
}

// Init
document.addEventListener('DOMContentLoaded', () => {
  loadConfig();
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, { action: 'getState' }, (response) => {
        if (chrome.runtime.lastError) {
          addLogEntry({ type: 'error', timestamp: Date.now(), message: 'Content script not found. Please reload the page.' });
        } else if (response && response.state) {
          updateUI(response.state);
        }
      });
    }
  });
});
