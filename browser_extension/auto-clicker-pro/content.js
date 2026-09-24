// content.js - AutoClicker Pro Main Engine (v2.0 - Oracle OTM/ADF Compatible)

console.log('[AutoClicker] Content script injected and ready (v2.0 OTM Edition).');

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

// --- Utility Functions ---
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

const isVisible = (el) => {
  if (!el) return false;
  try {
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return false;
    // Allow elements below/above viewport — they're still valid targets
    return true;
  } catch (e) {
    return false;
  }
};

const isDangerous = (el) => {
  try {
    const text = (el.innerText || el.textContent || '').toLowerCase();
    const id = (el.id || '').toLowerCase();
    const className = (el.className && typeof el.className === 'string' ? el.className : '').toLowerCase();
    const href = (el.getAttribute('href') || '').toLowerCase();

    for (const keyword of DANGER_KEYWORDS) {
      if (text.includes(keyword) || id.includes(keyword) || className.includes(keyword) || href.includes(keyword)) {
        return true;
      }
    }
  } catch (e) {}
  return false;
};

// --- Element Fingerprinting (survives ADF PPR DOM re-renders) ---
function getElementFingerprint(el) {
  try {
    const tag = el.tagName || '';
    const id = el.id || '';
    const text = (el.textContent || '').trim().substring(0, 80);
    const type = el.getAttribute('type') || '';
    const name = el.getAttribute('name') || '';
    const role = el.getAttribute('role') || '';
    const href = el.getAttribute('href') || '';
    const ariaLabel = el.getAttribute('aria-label') || '';
    const title = el.getAttribute('title') || '';
    // ADF-specific: onclick handler signature persists across PPR re-renders
    const onclick = (el.getAttribute('onclick') || '').substring(0, 100);

    return `${tag}|${id}|${text}|${type}|${name}|${role}|${href}|${ariaLabel}|${title}|${onclick}`;
  } catch (e) {
    return `fallback-${Math.random()}`;
  }
}

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
        backgroundColor: 'rgba(0,0,0,0.85)', color: 'white', borderRadius: '8px',
        fontFamily: 'sans-serif', fontSize: '12px', zIndex: '2147483647',
        display: 'none', pointerEvents: 'none', boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
        border: '1px solid rgba(233,69,96,0.5)', maxWidth: '300px', lineHeight: '1.5'
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

  updateStatus(clicked, skipped, errors, total, currentElInfo, scrollInfo) {
    if (this.statusBar) {
      this.statusBar.innerHTML = `
        <strong style="color:#e94560">🖱️ AutoClicker Pro</strong><br/>
        ✅ ${clicked} clicked | ⏭️ ${skipped} skipped | ❌ ${errors} errors<br/>
        🔍 ${total} found<br/>
        ${scrollInfo ? `📜 ${scrollInfo}<br/>` : ''}
        🎯 <span style="color:#aaa;font-size:11px">${currentElInfo}</span>
      `;
    }
  }

  highlightCurrent(el) {
    try {
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
        el.style.outline = '3px solid #e94560';
        el.style.boxShadow = '0 0 12px #e94560';
      }
    } catch (e) {}
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
        top: `${window.scrollY + rect.top + Math.max(0, rect.height / 2 - 4)}px`,
        left: `${window.scrollX + rect.left + Math.max(0, rect.width / 2 - 4)}px`,
        width: '8px', height: '8px', borderRadius: '50%',
        backgroundColor: color, opacity: '0.8', zIndex: '2147483645',
        border: '1px solid rgba(0,0,0,0.5)', pointerEvents: 'none'
      });
      if (this.overlayContainer) this.overlayContainer.appendChild(dot);
    } catch (e) {}
  }

  clear() {
    try {
      if (this.overlayContainer) this.overlayContainer.innerHTML = '';
      this.highlightCurrent(null);
      this.showStatus(false);
    } catch (e) {}
  }
}

// --- Element Discovery Engine ---
class ElementDiscoverer {
  constructor(config) {
    this.config = config;
    this.selectors = [
      // Standard HTML interactive elements
      'button', 'input[type="button"]', 'input[type="submit"]', 'input[type="reset"]',
      'input[type="checkbox"]', 'input[type="radio"]', 'select', 'textarea',

      // ARIA roles
      '[role="button"]', '[role="link"]', '[role="tab"]', '[role="menuitem"]',
      '[role="checkbox"]', '[role="radio"]', '[role="switch"]', '[role="option"]',
      '[role="treeitem"]', '[role="gridcell"]', '[role="combobox"]',
      '[role="menu"]', '[role="toolbar"]', '[role="tabpanel"]',

      // Event handler attributes
      '[onclick]', '[onmousedown]', '[onmouseup]', '[ontouchstart]',

      // SAP UI5 components
      '[data-sap-ui]', '.sapMBtn', '.sapMList', '.sapMTile', '.sapUiBtn',

      // Oracle ADF components (uncompressed class names)
      '[class*="af_commandButton"]', '[class*="af_commandLink"]',
      '[class*="af_button"]', '[class*="af_link"]',
      '[class*="af_commandMenuItem"]', '[class*="af_menuItem"]',
      '[class*="af_tab"]', '[class*="af_panelTabbed"]',
      '[class*="af_treeNode"]', '[class*="af_selectOneChoice"]',
      '[class*="af_selectBooleanCheckbox"]', '[class*="af_selectBooleanRadio"]',
      '[class*="af_commandImageLink"]', '[class*="af_commandToolbarButton"]',
      '[class*="af_toolbar"]', '[class*="af_inputText"]',
      '[class*="af_selectOneRadio"]', '[class*="af_selectManyCheckbox"]',
      '[class*="af_panelAccordion"]', '[class*="af_showDetailItem"]',

      // Oracle ADF generated ID patterns (ADF uses predictable suffixes)
      '[id*=":cb"]',    // commandButton
      '[id*=":cl"]',    // commandLink
      '[id*=":sdi"]',   // showDetailItem / disclosure
      '[id*=":sbc"]',   // selectBooleanCheckbox
      '[id*=":soc"]',   // selectOneChoice
      '[id*=":it"]',    // inputText
      '[id*=":tab"]',   // tab
      '[id*=":mi"]',    // menuItem
      '[id*=":cil"]',   // commandImageLink

      // Oracle ADF clickable patterns
      'a[onclick*="_chain"]',       // ADF event chain handler
      'a[onclick*="submitForm"]',   // ADF form submission
      'a[onclick*="AdfPage"]',      // ADF page handler
      'a[onclick*="AdfAction"]',    // ADF action handler
      'img[onclick]',               // Icon buttons in OTM
      'td[onclick]',                // Table cell clicks in OTM
      'tr[onclick]',                // Table row clicks

      // OTM-specific navigation
      '[class*="GlobalNav"]',
      '[class*="TabBar"]',
      '[class*="xnk"]',
    ];

    if (this.config.includeLinks) {
      this.selectors.push('a[href]');
    }
  }

  discover(root = document) {
    console.log('[AutoClicker] Discovering elements...');
    const elements = new Set();

    // 1. Standard selectors + ADF + OTM + ARIA
    const query = this.selectors.join(', ');
    try {
      const found = root.querySelectorAll(query);
      found.forEach(el => elements.add(el));
    } catch (e) {
      console.warn('[AutoClicker] Error querying selectors:', e);
    }

    // 2. Custom Components (Web Components) & Clickable divs (cursor:pointer / tabIndex)
    try {
      const allElements = root.querySelectorAll('*');
      allElements.forEach(el => {
        // Skip elements already marked as clicked
        if (el.getAttribute && el.getAttribute('data-acp-clicked') === '1') return;

        if (el.tagName && el.tagName.includes('-')) {
          elements.add(el);
        } else {
          try {
            const style = window.getComputedStyle(el);
            if (style.cursor === 'pointer' || el.tabIndex >= 0) {
              elements.add(el);
            }
          } catch (e) {}
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
      try {
        // Already clicked via data attribute (survives PPR)
        if (el.getAttribute && el.getAttribute('data-acp-clicked') === '1') return false;

        // Filter hidden elements
        if (this.config.skipHidden && !isVisible(el)) return false;

        // Safety check
        if (isDangerous(el)) return false;

        // User exclusions
        if (this.config.excludeSelectors && this.config.excludeSelectors.length > 0) {
          for (let sel of this.config.excludeSelectors) {
            try {
              if (sel.trim() && el.matches && el.matches(sel.trim())) return false;
            } catch (e) {}
          }
        }

        return true;
      } catch (e) {
        return false;
      }
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

// --- Click Engine (v2 - with scrolling + fingerprinting + PPR support) ---
class ClickEngine {
  constructor() {
    this.config = { ...DEFAULT_CONFIG };
    this.discoverer = new ElementDiscoverer(this.config);
    this.visuals = new VisualFeedback();

    this.state = {
      running: false,
      paused: false,
      // Triple-layer tracking
      clickedFingerprints: new Set(),     // Layer 1: String fingerprints (survives PPR re-renders)
      clickedElements: new WeakSet(),      // Layer 2: Object references (fast check for same nodes)
      // Stats
      clickedCount: 0,
      skippedCount: 0,
      errorCount: 0,
      elements: [],
      // Stuck detection
      lastClickedFP: null,
      sameRetries: 0,
      // Scrolling
      didFullPagePass: false,
      scrolledContainers: new WeakSet(),
      scrollRetries: 0,
    };

    this.mutationObserver = null;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.discoverer = new ElementDiscoverer(this.config);
  }

  async start() {
    if (this.state.running) return;
    console.log('[AutoClicker] Starting engine (v2 - OTM/ADF Compatible)...');
    this.state.running = true;
    this.state.paused = false;
    this.state.clickedCount = 0;
    this.state.skippedCount = 0;
    this.state.errorCount = 0;
    this.state.clickedFingerprints = new Set();
    this.state.clickedElements = new WeakSet();
    this.state.lastClickedFP = null;
    this.state.sameRetries = 0;
    this.state.didFullPagePass = false;
    this.state.scrolledContainers = new WeakSet();
    this.state.scrollRetries = 0;
    this.visuals.showStatus(true);

    this.setupDynamicDetection();

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
    reportProgress(this);
  }

  setupDynamicDetection() {
    try {
      this.mutationObserver = new MutationObserver(() => {
        // MutationObserver is active — re-scan will pick up new elements automatically
      });
      this.mutationObserver.observe(document.body, { childList: true, subtree: true });
    } catch (e) {
      console.warn('[AutoClicker] Could not set up MutationObserver:', e);
    }
  }

  // --- Auto-Scroll System ---
  async autoScroll() {
    const scrollStep = Math.floor(window.innerHeight * 0.8);
    const prevY = window.scrollY;

    window.scrollBy({ top: scrollStep, behavior: 'smooth' });
    await delay(1000); // Extra wait for ADF PPR / lazy content to load

    if (Math.abs(window.scrollY - prevY) > 10) {
      console.log(`[AutoClicker] Scrolled page to ${Math.round(window.scrollY)}/${Math.round(document.documentElement.scrollHeight - window.innerHeight)}`);
      return true;
    }

    // Main page fully scrolled — try scrollable containers (ADF tables, panels, etc.)
    return await this.scrollNextContainer();
  }

  async scrollNextContainer() {
    try {
      const candidates = document.querySelectorAll('*');
      for (const el of candidates) {
        try {
          if (this.state.scrolledContainers.has(el)) continue;

          const isScrollable = el.scrollHeight > el.clientHeight + 20;
          if (!isScrollable) continue;

          const style = window.getComputedStyle(el);
          const hasOverflow = ['auto', 'scroll'].includes(style.overflow) ||
                              ['auto', 'scroll'].includes(style.overflowY);
          if (!hasOverflow) continue;

          const prevTop = el.scrollTop;
          el.scrollBy({ top: el.clientHeight * 0.8, behavior: 'smooth' });
          await delay(1000);

          if (Math.abs(el.scrollTop - prevTop) > 10) {
            const elId = el.id ? `#${el.id}` : (el.className ? `.${String(el.className).split(' ')[0]}` : '');
            console.log(`[AutoClicker] Scrolled container ${el.tagName}${elId}`);
            return true;
          }
          this.state.scrolledContainers.add(el);
        } catch (e) {}
      }
    } catch (e) {
      console.warn('[AutoClicker] Error scrolling containers:', e);
    }
    return false;
  }

  // --- ADF PPR Wait ---
  async waitForPPR() {
    const maxWait = 5000;
    const start = Date.now();

    while (Date.now() - start < maxWait) {
      try {
        // Check if ADF is still processing (busy indicators)
        const busy = document.querySelector(
          '[class*="af_statusIndicator"], .x2h, [id*="::busy"], [class*="AFBusyIndicator"]'
        );
        const busyOverlay = document.querySelector(
          '.AFBlockingGlassPane, [class*="GlassPane"], [class*="af_dialog_blocked"]'
        );

        if (!busy && !busyOverlay) {
          await delay(200); // Small grace period after PPR completes
          return;
        }
      } catch (e) {
        return; // If we can't check, just continue
      }
      await delay(200);
    }
    console.warn('[AutoClicker] PPR wait timed out after 5s, continuing anyway');
  }

  // --- Main Click Loop (v2) ---
  async loop() {
    const MAX_SCROLL_RETRIES = 50;

    while (this.state.running && this.state.clickedCount < this.config.maxClicks) {
      if (this.state.paused) {
        await delay(500);
        continue;
      }

      // Wait for any ADF PPR to settle before discovering
      await delay(300);

      // Re-discover elements on every iteration
      this.state.elements = this.discoverer.discover();

      // Filter out already-clicked elements using triple-layer check
      const toClick = this.state.elements.filter(el => {
        try {
          // Layer 2: WeakSet fast check
          if (this.state.clickedElements.has(el)) return false;

          // Layer 3: Data attribute check (survives PPR)
          if (el.getAttribute && el.getAttribute('data-acp-clicked') === '1') {
            this.state.clickedElements.add(el);
            return false;
          }

          // Layer 1: Fingerprint check
          const fp = getElementFingerprint(el);
          if (this.state.clickedFingerprints.has(fp)) {
            this.state.clickedElements.add(el); // Cache ref too
            return false;
          }

          return true;
        } catch (e) {
          return false;
        }
      });

      // Update status bar
      this.visuals.updateStatus(
        this.state.clickedCount,
        this.state.skippedCount,
        this.state.errorCount,
        this.state.elements.length,
        toClick.length > 0 ? 'Clicking...' : 'Looking for more...',
        this.state.scrollRetries > 0 ? `Scroll pass ${this.state.scrollRetries}/${MAX_SCROLL_RETRIES}` : ''
      );

      if (toClick.length === 0) {
        // ── NO ELEMENTS: SCROLL instead of stopping ──
        const scrolled = await this.autoScroll();
        if (scrolled && this.state.scrollRetries < MAX_SCROLL_RETRIES) {
          this.state.scrollRetries++;
          console.log(`[AutoClicker] Scroll retry ${this.state.scrollRetries}/${MAX_SCROLL_RETRIES}`);
          continue; // Re-discover after scrolling
        }

        // Full-page second pass: scroll back to top
        if (!this.state.didFullPagePass) {
          this.state.didFullPagePass = true;
          console.log('[AutoClicker] First pass complete. Scrolling to top for final pass...');
          window.scrollTo({ top: 0, behavior: 'smooth' });
          await delay(1500);
          this.state.scrollRetries = 0;
          this.state.scrolledContainers = new WeakSet();
          continue;
        }

        console.log('[AutoClicker] Full page scanned. No more elements. Done.');
        this.stop();
        break;
      }

      // Reset scroll retries since we found elements
      this.state.scrollRetries = 0;

      const el = toClick[0];
      const fp = getElementFingerprint(el);

      // ── STUCK DETECTION ──
      if (fp === this.state.lastClickedFP) {
        this.state.sameRetries++;
        if (this.state.sameRetries >= 3) {
          console.warn(`[AutoClicker] Stuck on element (3x same fingerprint). Skipping: ${fp.substring(0, 80)}`);
          this.state.clickedFingerprints.add(fp);
          this.state.clickedElements.add(el);
          try { el.setAttribute('data-acp-clicked', '1'); } catch (e) {}
          this.state.skippedCount++;
          this.state.sameRetries = 0;
          continue;
        }
      } else {
        this.state.sameRetries = 0;
      }
      this.state.lastClickedFP = fp;

      // ── CLICK with timeout ──
      try {
        await Promise.race([
          this.clickElement(el, fp),
          new Promise((_, rej) => setTimeout(() => rej(new Error('Click Timeout (5s)')), 5000))
        ]);
      } catch (err) {
        console.error('[AutoClicker] Click failed/timed out:', err.message);
        this.visuals.markElement(el, 'error');
        this.state.clickedElements.add(el);
        this.state.clickedFingerprints.add(fp);
        try { el.setAttribute('data-acp-clicked', '1'); } catch (e) {}
        this.state.errorCount++;
      }

      // Wait between clicks
      await delay(this.config.clickDelay);
    }

    if (this.state.running && this.state.clickedCount >= this.config.maxClicks) {
      console.log('[AutoClicker] Max clicks reached.');
      this.stop();
    }
  }

  async clickElement(el, fp) {
    try {
      // Mark as clicked in all three layers
      this.state.clickedElements.add(el);
      this.state.clickedFingerprints.add(fp);
      try { el.setAttribute('data-acp-clicked', '1'); } catch (e) {}

      if (this.config.skipHidden && !isVisible(el)) {
        this.visuals.markElement(el, 'skipped');
        this.state.skippedCount++;
        return;
      }

      const elInfo = `<${el.tagName.toLowerCase()}>${el.id ? '#' + el.id : ''}${el.textContent ? ' "' + el.textContent.trim().substring(0, 30) + '"' : ''}`;
      console.log(`[AutoClicker] Clicking ${elInfo}`);

      this.visuals.highlightCurrent(el);
      this.visuals.updateStatus(
        this.state.clickedCount,
        this.state.skippedCount,
        this.state.errorCount,
        this.state.elements.length,
        elInfo,
        ''
      );

      // Scroll into view
      try {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        await delay(200);
      } catch (e) {}

      // Handle link navigation prevention
      const clickPreventer = (e) => {
        if (this.config.preventNavigation) {
          e.preventDefault();
          e.stopPropagation();
        }
      };

      if (el.tagName && el.tagName.toLowerCase() === 'a') {
        el.addEventListener('click', clickPreventer, true);
      }

      // Simulate full event chain
      this.simulateEvents(el);

      this.state.clickedCount++;
      this.visuals.markElement(el, 'clicked');

      // Cleanup link preventer
      if (el.tagName && el.tagName.toLowerCase() === 'a') {
        setTimeout(() => {
          try { el.removeEventListener('click', clickPreventer, true); } catch (e) {}
        }, 100);
      }

      // Wait for ADF PPR to complete before moving on
      await this.waitForPPR();

      // Try to close any modals that might have appeared
      await this.handleModals();

    } catch (e) {
      console.error('[AutoClicker] Error clicking element:', e);
      this.visuals.markElement(el, 'error');
      this.state.errorCount++;
    }
  }

  simulateEvents(el) {
    try {
      const rect = el.getBoundingClientRect();
      const x = rect.left + rect.width / 2;
      const y = rect.top + rect.height / 2;

      const commonOpts = {
        bubbles: true,
        cancelable: true,
        view: window,
        clientX: x,
        clientY: y,
        screenX: x,
        screenY: y,
        button: 0,
        buttons: 1
      };

      const events = [
        new PointerEvent('pointerenter', { ...commonOpts, bubbles: false }),
        new MouseEvent('mouseenter', { ...commonOpts, bubbles: false }),
        new MouseEvent('mouseover', commonOpts),
        new PointerEvent('pointerdown', commonOpts),
        new MouseEvent('mousedown', commonOpts),
        new PointerEvent('pointerup', commonOpts),
        new MouseEvent('mouseup', commonOpts),
        new MouseEvent('click', commonOpts)
      ];

      for (const ev of events) {
        try { el.dispatchEvent(ev); } catch (e) {}
      }
    } catch (e) {}

    // Fallback: native click
    try {
      if (typeof el.click === 'function') {
        el.click();
      }
    } catch (e) {}
  }

  async handleModals() {
    try {
      await delay(300); // Brief wait for modal to appear
      const closeSelectors = [
        'button[aria-label="Close" i]',
        '.close',
        '.modal-close',
        '[class*="modal-close" i]',
        '[id*="close-modal" i]',
        // ADF-specific dialog close buttons
        '[class*="af_dialog_close"]',
        '[id*="::close"]',
        'a[title="Close" i]',
        'img[title="Close" i]',
      ].join(', ');

      const closeButtons = document.querySelectorAll(closeSelectors);
      for (const btn of closeButtons) {
        try {
          if (isVisible(btn) && !this.state.clickedElements.has(btn)) {
            console.log('[AutoClicker] Closing detected modal/dialog.');
            btn.click();
            this.state.clickedElements.add(btn);
            const fp = getElementFingerprint(btn);
            this.state.clickedFingerprints.add(fp);
            await delay(300);
          }
        } catch (e) {}
      }
    } catch (e) {}
  }
}

// --- Progress Reporting ---
function reportProgress(engineInstance) {
  try {
    const totalFound = engineInstance.state.elements ? engineInstance.state.elements.length : 0;
    const clicked = engineInstance.state.clickedCount || 0;
    const skipped = engineInstance.state.skippedCount || 0;
    const errors = engineInstance.state.errorCount || 0;
    const status = engineInstance.state.running ? (engineInstance.state.paused ? 'paused' : 'running') : 'stopped';

    chrome.runtime.sendMessage({
      type: 'STATE_UPDATE',
      state: {
        status: status,
        stats: {
          found: totalFound,
          clicked: clicked,
          skipped: skipped,
          errors: errors
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
              skipped: engine.state.skippedCount || 0,
              errors: engine.state.errorCount || 0
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
  return true;
};

chrome.runtime.onMessage.addListener(window.autoClickerListener);
