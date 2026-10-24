# wayback (littlespidy)

Burp Suite Montoya Extension for automated Wayback Machine historical reconnaissance and active directory listing detection.

Created with the help of an AI Agent and littlespidy.
Based on the original concept by FR13ND0x7F (WaybackLister).

---

## Features

- **Montoya API Standard**: Built using Burp Suite modern Montoya API (`net.portswigger.burp.extensions:montoya-api:2026.4`).
- **Dedicated Multi-Domain Tab Model**: Each domain scan operates in its own dedicated parent tab (`#<ID> <domain> [x]`) with double-click in-place renaming and close button.
- **Top-Level Configuration Parent Tab**: Global directory listing detection signatures, CDX URL template, standard browser User-Agent, and network retries shared across all domain scans.
- **Realistic Browser User-Agent**: Uses standard realistic browser User-Agent (`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`) to avoid triggering anti-bot WAF rules.
- **Strict Child Tab Hierarchy**:
  1. **Path**: Harvested archived URL paths from Wayback CDX, probe status (Checked/Pending/Failed), and directory probe result (Open Listing, Normal Page, 403 Forbidden, Not Directory).
  2. **Subdomain**: Discovered subdomains and associated path counts.
  3. **Directory Listing**: Confirmed open directory findings table with parallel side-by-side HTTP Request & Response viewers.
- **Right-Click Context Menus**: Clean tables without button clutter:
  - Findings: Send to Repeater, Send to Intruder, Open in Browser, Copy URL.
  - Paths: Re-test Path, Send to Repeater, Add to Burp Site Map, Copy Path.
  - Subdomains: Scan in Dedicated Tab, Add to Burp Target Scope, Copy Subdomain.
- **Parallel HTTP Request & Response Inspector**: 50%/50% side-by-side horizontal split pane displaying exact HTTP Request and Response for detected directory listings.
- **Persistent Session Storage**: Startup prompt (Open Existing, Create New, Start Temporary), debounced atomic auto-saving (1500ms), manual toolbar controls (`New Session`, `Open Session`, `Save`, `Save As...`, `Offboard Session`), and status indicator.
- **Burp Suite Context Menu Integration**: Right click any request in Proxy History, Target Site Map, Repeater, or Logger -> "Send Domain to wayback" to immediately open or focus a dedicated scan tab.

---

## Installation

1. Clone repository or navigate to extension folder:
   ```bash
   cd Wayback_littlespidy
   ```
2. Build the fat-JAR artifact:
   ```bash
   ./gradlew clean test jar
   ```
3. Locate compiled release JAR:
   `Wayback_littlespidy/build/libs/wayback-littlespidy-1.0.0.jar`
4. Load into Burp Suite:
   - Navigate to **Extensions** -> **Installed**.
   - Click **Add**.
   - Extension Type: **Java**.
   - Select `Wayback_littlespidy/build/libs/wayback-littlespidy-1.0.0.jar`.
   - The **wayback** suite tab will appear.

---

## Usage Workflow

1. **Initialize Session**: Choose to open an existing session, create a new session bound to a directory, or start in temporary in-memory mode.
2. **Start Domain Scan**:
   - Enter target domain in the toolbar (e.g. `testphp.vulnweb.com`).
   - Check `Auto-discover Subdomains (*.domain/*)` if you want to harvest paths across subdomains.
   - Click `Start Scan`.
3. **Inspect Harvested Data**:
   - Tab 1 (`Path`): Review discovered paths and probe statuses.
   - Tab 2 (`Subdomain`): Review subdomains; right-click any subdomain to launch "Scan in Dedicated Tab".
   - Tab 3 (`Directory Listing`): View detected open directories and analyze request/response side-by-side.
4. **Send to Core Burp Tools**: Right click any finding or path to send directly to Repeater, Intruder, or Burp Site Map.
5. **Configure Signatures**: Switch to the `Configuration` parent tab to add or customize signature substrings (e.g. `Index of /`, `Parent Directory</a>`).

---

## Testing & Quality Assurance

Run test suite:
```bash
./gradlew test
```

All tests execute in headless mode using JUnit Jupiter 5.
