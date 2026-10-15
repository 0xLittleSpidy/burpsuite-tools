# jwt_playbook (Burp Suite extension)

`jwt_playbook` is a Montoya API extension for inspecting JWTs offline and carrying out controlled, user initiated JWT and authorization tests in Burp Suite. Generated attack tokens are shown for review and are never sent automatically.

## Tabs

### Offline Analysis

- Extract JWTs from selected Burp traffic, headers, cookies, and message bodies through the context menu.
- Decode and compare an arbitrary number of token headers and claims, highlight differences, filter claims, translate standard timestamps, and import/export token sessions and TSV reports.
- Keep token slots available to the Attack tab's access matrix.

### Attack

**JWT Attack Workbench** builds and analyzes variants locally:

- `alg=none` with common case variants, null signature, blank HMAC secret, HMAC confusion using supplied public-key text, and ECDSA psychic-signature vectors.
- `kid` SQL/path/command/LDAP/raw injection strings; embedded JWK, `jku`, `x5u`, and `x5c` header injection templates.
- Claim type/null/special-character/oversized-value fuzz variants for every claim (or one selected claim), with a configurable maximum string length, and `exp`/`nbf`/`iat` timestamp tampering. Generate one technique or batch-generate the complete local variant set.
- Offline HMAC secret checks against blank and user-supplied candidate secrets; basic token structure, algorithm and claims checks.
- Copy a selected generated JWT or load it into an Offline Analysis token slot.

**Keys & Verification** adds local key generation (HMAC secrets, RSA 2048, P-256/P-384/P-521 EC, and Ed25519), JWT create/sign/re-sign for HS/RS/PS/ES/EdDSA, PEM signature verification, public JWK export, and signature verification against a JWKS endpoint through Burp's HTTP API. HMAC, RSA PKCS#1, RSA-PSS, ECDSA JOSE signatures, and EdDSA use the selected JWT algorithm. Asymmetric key generation also creates a self-signed certificate for `x5c` tests.

**Live JWT Probes** adds requests selected in Burp through the context menu, then sends pasted or imported generated variants to those requests. It supports header, cookie, query parameter, and form-body placement, custom field names and header prefixes, serial execution, an adjustable inter-request delay, cancellation, and an optional expected-success canary. Results compare status and response size to each captured baseline and flag leads such as 5xx responses, 401/403-to-2xx changes, matching canaries, or unusual body-size changes. These are triage signals for manual review, not confirmed findings.

The Attack Workbench can start a stoppable local key-material server that serves `/jwks.json` and `/cert.pem`. Bind address, advertised host, and port are configurable (the default bind is loopback); generated `jku` and `x5u` variants use those endpoints, while `x5c` uses the matching generated certificate.

The **Token Access Matrix** preserves the original request replay workflow: queue requests from Burp, substitute loaded tokens or test without authentication, inspect responses, throttle/pause/stop replay, and export results. Together with Live JWT Probes, this adapts request replay and attack-variant testing to Burp's existing HTTP requests.

## Coverage notes

The feature map was reviewed against the upstream [jwt_tool README](https://github.com/ticarpi/jwt_tool) and [JWTop README](https://github.com/cerberauth/jwtop). The extension implements local JWT inspection, key workflows, exploit-variant generation, candidate-secret checks, external John/hashcat dictionary cracking, and active probing of requests explicitly queued from Burp. `jku` and `x5u` values are editable URLs. For meaningful embedded-JWK checks, generate a key pair in Keys & Verification; the workbench then embeds that public JWK and signs with the corresponding private key. An `x5c` value accepts a JSON array or one base64 DER certificate string. John and hashcat are optional host tools; choose a wordlist, executable (PATH or file picker), and timeout to invoke them.

## Build

Requires Java 17 or later:

```bash
./gradlew jar
```

The extension JAR is `build/libs/jwt_playbook-1.0.0.jar`. Load it in Burp via **Extensions → Installed → Add → Java**.

Use active probes only against systems you own or are explicitly authorized to test. Review generated requests before replaying them.
