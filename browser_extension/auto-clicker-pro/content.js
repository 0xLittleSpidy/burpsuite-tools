// content.js - AutoClicker Pro Main Engine

console.log('[AutoClicker] Content script injected and ready.');

// --- Configuration ---
const DEFAULT_CONFIG = {
  clickDelay: 500,
  includeLinks: false,
  includeIframes: true,
  includeShadowDOM: true,
  maxDepth: 3,
  skipHidden: true,
  preventNavigation: true,
  clickOrder: 'dom', // 'dom' | 'visual' | 'random'
  elementFilter: '*',
  excludeSelectors: [],
  maxClicks: 1000
};

// --- Safety Exclusions ---
const DANGER_KEYWORDS = ['logout', 'sign out', 'signout', 'log out', 'delete', 'remove', 'destroy', 'terminate'];
const DANGER_SELECTORS = [
  '[id*="logout" i]', '[class*="logout" i]', '[href*="logout" i]',
  '[id*="delete" i]', '[class*="delete" i]',
  'button:contains("Log out")', 'button:contains("Sign out")' // Custom selector heuristic handled in JS
];

// --- Utility Functions ---
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const isVisible = (el) => {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = el.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
};

const isDangerous = (el) => {
  const text = (el.innerText || el.textContent || '').toLowerCase();
  const id = (el.id || '').toLowerCase();
  const className = (el.className && typeof el.className === 'string' ? el.className : '').toLowerCase();
  const href = (el.getAttribute('href') || '').toLowerCase();

  for (const keyword of DANGER_KEYWORDS) {
    if (text.includes(keyword) || id.includes(keyword) || className.includes(keyword) || href.includes(keyword)) {
      return true;
    }
  }
  return false;
};

// --- Visual Feedback System ---
class VisualFeedback {
  constructor() {
    this.statusBar = null;
    this.overlayContainer = null;
    this.currentHighlight = null;
    this.setup();
  }

  setup() {
    try {
      this.statusBar = document.createElement('div');
      this.statusBar.id = 'auto-clicker-status-bar';
      Object.assign(this.statusBar.style, {
        position: 'fixed', bottom: '10px', right: '10px', padding: '10px 15px',
        backgroundColor: 'rgba(0,0,0,0.8)', color: 'white', borderRadius: '5px',
        fontFamily: 'sans-serif', fontSize: '12px', zIndex: '2147483647', // Max z-index
        display: 'none', pointerEvents: 'none', boxShadow: '0 4px 6px rgba(0,0,0,0.3)'
      });
      document.documentElement.appendChild(this.statusBar);

      this.overlayContainer = document.createElement('div');
      this.overlayContainer.id = 'auto-clicker-overlay-container';
      Object.assign(this.overlayContainer.style, {
        position: 'absolute', top: '0', left: '0', width: '100%', height: '100%',
        pointerEvents: 'none', zIndex: '2147483646'
      });
      document.documentElement.appendChild(this.overlayContainer);
    } catch (e) {
      console.error('[AutoClicker] Error setting up visual feedback:', e);
    }
  }

  showStatus(visible) {
    if (this.statusBar) this.statusBar.style.display = visible ? 'block' : 'none';
  }

  updateStatus(progress, count, currentElInfo) {
    if (this.statusBar) {
      this.statusBar.innerHTML = `
        <strong>AutoClicker Pro</strong><br/>
        Progress: ${progress}% (${count} clicked)<br/>
        Current: <span style="color:#aaa">${currentElInfo}</span>
      `;
    }
  }

  highlightCurrent(el) {
    if (this.currentHighlight) {
      this.currentHighlight.style.outline = this.currentHighlight.dataset.oldOutline || '';
      this.currentHighlight.style.boxShadow = this.currentHighlight.dataset.oldBoxShadow || '';
      this.currentHighlight.style.transition = this.currentHighlight.dataset.oldTransition || '';
    }
    if (el) {
      this.currentHighlight = el;
      el.dataset.oldOutline = el.style.outline;
      el.dataset.oldBoxShadow = el.style.boxShadow;
      el.dataset.oldTransition = el.style.transition;
      
      el.style.transition = 'all 0.2s ease-in-out';
      el.style.outline = '3px solid #00f';
      el.style.boxShadow = '0 0 10px #00f';
    }
  }

  markElement(el, status) {
    try {
      const rect = el.getBoundingClientRect();
      const dot = document.createElement('div');
      
      let color = 'gray';
      if (status === 'clicked') color = '#0f0';
      else if (status === 'skipped') color = '#ff0';
      else if (status === 'error') color = '#f00';

      Object.assign(dot.style, {
        position: 'absolute',
        top: `${window.scrollY + rect.top + Math.max(0, rect.height/2 - 5)}px`,
        left: `${window.scrollX + rect.left + Math.max(0, rect.width/2 - 5)}px`,
        width: '10px', height: '10px', borderRadius: '50%',
        backgroundColor: color, opacity: '0.7', zIndex: '2147483645',
        border: '1px solid black', pointerEvents: 'none'
      });
      
      if (this.overlayContainer) {
         this.overlayContainer.appendChild(dot);
      }
    } catch (e) {
      console.warn('[AutoClicker] Could not mark element', e);
    }
  }
  
  clear() {
    if (this.overlayContainer) this.overlayContainer.innerHTML = '';
    this.highlightCurrent(null);
    this.showStatus(false);
  }
}

// --- Element Discovery Engine ---
class ElementDiscoverer {
  constructor(config) {
    this.config = config;
    this.selectors = [
      'button', 'input[type="button"]', 'input[type="submit"]', 'input[type="reset"]',
      'input[type="checkbox"]', 'input[type="radio"]', 'select', 'textarea',
      '[role="button"]', '[role="link"]', '[role="tab"]', '[role="menuitem"]',
      '[role="checkbox"]', '[role="radio"]', '[role="switch"]', '[role="option"]',
      '[role="treeitem"]', '[role="gridcell"]', '[role="combobox"]',
      '[onclick]', '[onmousedown]', '[onmouseup]', '[ontouchstart]',
      '[data-sap-ui]', '.sapMBtn', '.sapMList', '.sapMTile', '.sapUiBtn'
    ];
    if (this.config.includeLinks) {
      this.selectors.push('a[href]');
    }
  }

  discover(root = document) {
    console.log('[AutoClicker] Discovering elements...');
    const elements = new Set();

    // 1. Standard HTML & ARIA & SAP & Event Attributes
    const query = this.selectors.join(', ');
    try {
      const found = root.querySelectorAll(query);
      found.forEach(el => elements.add(el));
    } catch (e) {
      console.warn('[AutoClicker] Error querying selectors:', e);
    }

    // 2. Custom Components (Hyphen tags) & Clickable Divs (Cursor)
    try {
      const allElements = root.querySelectorAll('*');
      allElements.forEach(el => {
        if (el.tagName.includes('-')) {
          elements.add(el);
        } else {
          const style = window.getComputedStyle(el);
          if (style.cursor === 'pointer' || el.tabIndex >= 0) {
            elements.add(el);
          }
        }
      });
    } catch (e) {
      console.warn('[AutoClicker] Error scanning all elements:', e);
    }

    // 3. Shadow DOM Traversal
    if (this.config.includeShadowDOM) {
      this._traverseShadowDOM(root, elements);
    }

    // 4. Iframe Traversal
    if (this.config.includeIframes) {
      this._traverseIframes(root, elements);
    }

    return Array.from(elements).filter(el => {
      // Filter out elements based on config
      if (this.config.skipHidden && !isVisible(el)) return false;
      if (isDangerous(el)) return false;
      
      // Handle user exclusions
      if (this.config.excludeSelectors && this.config.excludeSelectors.length > 0) {
         try {
           for(let sel of this.config.excludeSelectors) {
             if (el.matches && el.matches(sel)) return false;
           }
         } catch(e) {}
      }
      
      return true;
    });
  }

  _traverseShadowDOM(root, elementsSet) {
    try {
      const all = root.querySelectorAll('*');
      all.forEach(el => {
        if (el.shadowRoot) {
          const shadowElements = this.discover(el.shadowRoot);
          shadowElements.forEach(se => elementsSet.add(se));
        }
      });
    } catch (e) {
      console.warn('[AutoClicker] Shadow DOM traversal error:', e);
    }
  }

  _traverseIframes(root, elementsSet) {
    try {
      const iframes = root.querySelectorAll('iframe');
      iframes.forEach(iframe => {
        try {
          // Attempt to access same-origin iframe
          const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
          if (iframeDoc) {
             const iframeElements = this.discover(iframeDoc);
             iframeElements.forEach(ie => elementsSet.add(ie));
          }
        } catch (e) {
          // Cross-origin iframe, ignore
        }
      });
    } catch (e) {
       console.warn('[AutoClicker] Iframe traversal error:', e);
    }
  }
}

// --- Click Engine ---
class ClickEngine {
  constructor() {
    this.config = { ...DEFAULT_CONFIG };
    this.discoverer = new ElementDiscoverer(this.config);
    this.visuals = new VisualFeedback();
    
    this.state = {
      running: false,
      paused: false,
      clickedElements: new WeakSet(),
      clickedCount: 0,
      elements: [],
      currentIndex: 0
    };
    
    this.mutationObserver = null;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.discoverer = new ElementDiscoverer(this.config);
  }

  async start() {
    if (this.state.running) return;
    console.log('[AutoClicker] Starting engine...');
    this.state.running = true;
    this.state.paused = false;
    this.state.clickedCount = 0;
    this.state.clickedElements = new WeakSet();
    this.visuals.showStatus(true);
    
    this.setupDynamicDetection();
    
    // Prevent navigation globally if configured
    if (this.config.preventNavigation) {
      window.addEventListener('beforeunload', this.preventNavHandler);
    }

    await this.loop();
  }
  
  preventNavHandler = (e) => {
    e.preventDefault();
    e.returnValue = '';
  }

  pause() {
    console.log('[AutoClicker] Paused.');
    this.state.paused = true;
  }

  resume() {
    console.log('[AutoClicker] Resumed.');
    this.state.paused = false;
  }

  stop() {
    console.log('[AutoClicker] Stopped.');
    this.state.running = false;
    this.visuals.clear();
    if (this.mutationObserver) {
      this.mutationObserver.disconnect();
    }
    if (this.config.preventNavigation) {
      window.removeEventListener('beforeunload', this.preventNavHandler);
    }
  }

  setupDynamicDetection() {
    this.mutationObserver = new MutationObserver((mutations) => {
      // Trigger a re-scan if significant DOM changes occur
      // Throttling could be added here in the future
    });
    this.mutationObserver.observe(document.body, { childList: true, subtree: true });
  }

  async loop() {
    while (this.state.running && this.state.clickedCount < this.config.maxClicks) {
      if (this.state.paused) {
        await delay(500);
        continue;
      }

      // Re-discover on every iteration to handle dynamic content
      this.state.elements = this.discoverer.discover();
      
      // Filter out already clicked
      const toClick = this.state.elements.filter(el => !this.state.clickedElements.has(el));

      if (toClick.length === 0) {
        console.log('[AutoClicker] No more unclicked elements found. Stopping.');
        this.stop();
        break;
      }

      const el = toClick[0];
      
      // Infinite loop check via timeout bounds
      const clickPromise = this.clickElement(el);
      const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Click Timeout')), 5000));
      
      try {
        await Promise.race([clickPromise, timeoutPromise]);
      } catch (err) {
        console.error('[AutoClicker] Click operation failed or timed out:', err);
        this.visuals.markElement(el, 'error');
        this.state.clickedElements.add(el); // Mark as clicked so we skip it next time
      }
      
      // Wait between clicks
      await delay(this.config.clickDelay);
    }
    
    if (this.state.clickedCount >= this.config.maxClicks) {
        console.log('[AutoClicker] Max clicks reached.');
        this.stop();
    }
  }

  async clickElement(el) {
    try {
      this.state.clickedElements.add(el);
      
      if (this.config.skipHidden && !isVisible(el)) {
        this.visuals.markElement(el, 'skipped');
        return;
      }

      const elInfo = `<${el.tagName.toLowerCase()}>${el.id ? '#' + el.id : ''}`;
      console.log(`[AutoClicker] Clicking ${elInfo}`);
      
      this.visuals.highlightCurrent(el);
      this.visuals.updateStatus(
        Math.round((this.state.clickedCount / this.config.maxClicks) * 100), 
        this.state.clickedCount, 
        elInfo
      );

      // Scroll into view
      try {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        await delay(100);
      } catch(e) {}

      // Handle Link navigation prevention
      const clickPreventer = (e) => {
        if (this.config.preventNavigation) {
          e.preventDefault();
        }
      };
      
      if (el.tagName.toLowerCase() === 'a') {
        el.addEventListener('click', clickPreventer);
      }

      // Simulate full event chain
      this.simulateEvents(el);
      
      this.state.clickedCount++;
      this.visuals.markElement(el, 'clicked');

      // Cleanup
      if (el.tagName.toLowerCase() === 'a') {
        setTimeout(() => el.removeEventListener('click', clickPreventer), 50);
      }
      
      // Close Modals logic
      this.handleModals();

    } catch (e) {
      console.error('[AutoClicker] Error clicking element:', e);
      this.visuals.markElement(el, 'error');
    }
  }

  simulateEvents(el) {
    const events = [
      new PointerEvent('pointerenter', { bubbles: true, cancelable: true }),
      new MouseEvent('mouseenter', { bubbles: true, cancelable: true }),
      new PointerEvent('pointerdown', { bubbles: true, cancelable: true }),
      new MouseEvent('mousedown', { bubbles: true, cancelable: true }),
      new PointerEvent('pointerup', { bubbles: true, cancelable: true }),
      new MouseEvent('mouseup', { bubbles: true, cancelable: true }),
      new MouseEvent('click', { bubbles: true, cancelable: true })
    ];

    let success = false;
    for (const ev of events) {
      try {
        el.dispatchEvent(ev);
        success = true;
      } catch(e) {}
    }
    
    // Fallback
    if (!success || typeof el.click === 'function') {
      try {
        el.click();
      } catch(e) {}
    }
  }

  handleModals() {
    try {
        const closeSelectors = 'button[aria-label="Close" i], .close, .modal-close, [class*="modal-close" i], [id*="close-modal" i]';
        const closeButtons = document.querySelectorAll(closeSelectors);
        closeButtons.forEach(btn => {
            if (isVisible(btn) && !this.state.clickedElements.has(btn)) {
                console.log('[AutoClicker] Attempting to close detected modal.');
                btn.click();
                this.state.clickedElements.add(btn);
            }
        });
    } catch(e){}
  }
}

// --- Progress Reporting ---
function reportProgress(engine) {
  try {
    const totalFound = engine.state.elements ? engine.state.elements.length : 0;
    const clicked = engine.state.clickedCount || 0;
    const status = engine.state.running ? (engine.state.paused ? 'paused' : 'running') : 'stopped';

    chrome.runtime.sendMessage({
      type: 'STATE_UPDATE',
      state: {
        status: status,
        stats: {
          found: totalFound,
          clicked: clicked,
          skipped: 0,
          errors: 0
        }
      }
    }).catch(() => {});
  } catch (e) {
    // Popup might be closed, ignore
  }
}

// --- Initialization & Message Handling ---
const engine = new ClickEngine();

// Report progress periodically while running
setInterval(() => {
  if (engine.state.running) {
    reportProgress(engine);
  }
}, 1000);

// In case the script is reinjected
if (window.autoClickerListener) {
    chrome.runtime.onMessage.removeListener(window.autoClickerListener);
}

window.autoClickerListener = (request, sender, sendResponse) => {
  console.log('[AutoClicker] Received message:', request.action);
  
  try {
    switch (request.action) {
      case 'start':
        if (request.config) engine.updateConfig(request.config);
        engine.start();
        reportProgress(engine);
        sendResponse({ status: 'started' });
        break;
      case 'pause':
        engine.pause();
        reportProgress(engine);
        sendResponse({ status: 'paused' });
        break;
      case 'resume':
        engine.resume();
        reportProgress(engine);
        sendResponse({ status: 'resumed' });
        break;
      case 'stop':
        engine.stop();
        reportProgress(engine);
        sendResponse({ status: 'stopped' });
        break;
      case 'rescan':
        console.log('[AutoClicker] Re-scanning elements...');
        engine.state.elements = engine.discoverer.discover();
        reportProgress(engine);
        sendResponse({ status: 'rescanned', found: engine.state.elements.length });
        break;
      case 'updateConfig':
        if (request.config) engine.updateConfig(request.config);
        sendResponse({ status: 'config_updated' });
        break;
      case 'getStatus':
      case 'getState':
        const totalFound = engine.state.elements ? engine.state.elements.length : 0;
        const status = engine.state.running ? (engine.state.paused ? 'paused' : 'running') : 'stopped';
        sendResponse({ 
          state: {
            status: status,
            stats: {
              found: totalFound,
              clicked: engine.state.clickedCount || 0,
              skipped: 0,
              errors: 0
            }
          }
        });
        break;
      default:
        sendResponse({ status: 'unknown_command' });
    }
  } catch (e) {
    console.error('[AutoClicker] Error handling message:', e);
    sendResponse({ status: 'error', message: e.message });
  }
  return true; // Keep channel open for async response
};

chrome.runtime.onMessage.addListener(window.autoClickerListener);
