# Secret & Sensitive Pattern Reference (`patterns.md`)

This single file contains all regular expressions, two-stage refiners, and extraction keywords for secret detection across Burp extensions, Bambdas, and BChecks.

---

## 1. Cloud Storage & URLs (Two-Stage Refiners)

| Service | Primary Anchor Regex | Refiner Regex (Lookback 64 chars) | Require Refiner |
|---|---|---|---|
| **AWS S3 Bucket** | `s3(\.dualstack\|-acce(lerate\|sspoint))?\.([a-z]{1,8}-[a-z]{1,16}-\d{1,3}\.)?amazonaws\.com` | `[a-z\d\-]{3,63}\.$` | `true` |
| **Azure Blob Storage** | `blob\.core\.windows\.net` | `[a-z\d\-]{3,63}\.$` | `true` |
| **Firebase Database** | `\.(firebase(io\.com\|database\.app))` | `[0-9a-zA-Z\.\-]{1,64}$` | `true` |
| **Google Cloud Storage** | `\bgs://[a-z\d\-]{3,63}\b` | *None* | `false` |
| **Amazon ARN** | `\barn:aws(-(cn\|us-gov\|iso-[bcd]))?:[\w/.\-]{1,63}:([\w/.\-]{0,63}:){2}([\w:/.\-]{0,1023})\b` | *None* | `false` |
| **MS Teams Webhook** | `\.webhook\.office\.com` | `\w+$` | `true` |
| **Office 365 Webhook** | `outlook\.office(365)?\.com/webhook/[\w\-@]{1,128}` | *None* | `false` |
| **Slack Webhook** | `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}` | *None* | `false` |

---

## 2. API Tokens & Credentials

| Token Name | Regex Pattern | Notes |
|---|---|---|
| **AWS Access Key ID** | `\bA(BIA\|CCA\|GPA\|I(DA\|PA)\|KIA\|N(PA\|VA)\|PKA\|ROA\|S(CA\|IA))[a-zA-Z0-9]{16,17}\b` | `AKIA` = user/SES, `ASIA` = temp STS, `AROA` = role |
| **AWS Secret Access Key** | `(?i)aws(?:_secret)?(?:_access)?(?:_key)?\s*[:=]\s*['"]([0-9a-zA-Z/+=]{40})['"]` | 40-char base64 string |
| **Amazon MWS Token** | `(?i)amzn\.mws\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}` | MWS merchant token |
| **Google API Key** | `\bAIza[0-9A-Za-z\-_]{35}\b` | AIza + 35 chars |
| **Google OAuth Token** | `\bya29\.[0-9A-Za-z\-_]{32,64}\b` | Bearer token |
| **Google OAuth Client ID** | Primary: `\.apps\.googleusercontent\.com` / Refiner: `\d{1,20}-\w{32}$` | Two-stage refiner |
| **Google OAuth Client Secret**| `\bGOCSPX-[0-9a-zA-Z\-_]{28}\b` | GOCSPX- + 28 chars |
| **OpenAI API Key** | `\bsk-[a-zA-Z0-9]{40,128}(?![\w\-])\b` | Standard `sk-` & project `sk-proj-` |
| **GitHub Classic PAT** | `\bgh[pousr]_[a-zA-Z0-9]{36,40}\b` | `ghp_` personal, `gho_` oauth, `ghs_` server |
| **GitHub Fine-Grained PAT**| `\bgithub_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}\b` | Fine-grained token |
| **Slack Bot/User Token** | `\bx(ox[psboare]\|app)(-[a-zA-Z0-9]{1,64}){1,5}\b` | `xoxb-` bot, `xoxp-` user, `xapp-` app |
| **Stripe Secret Key** | `\b[rs]k_(live\|test)_[0-9a-zA-Z]{24,34}\b` | Secret or restricted key |
| **Stripe Webhook Secret** | `\bwhsec_[0-9a-zA-Z]{32}\b` | Webhook signing secret |
| **Square Token** | `\bsq0(atp\|csp\|idp)-[0-9A-Za-z\-_]{22,43}\b` | `idp` client ID, `csp` secret, `atp` app |
| **Twilio API Key** | `\bSK[0-9a-zA-Z]{32}\b` | Twilio API key |
| **SendGrid API Key** | `\bSG\.[a-zA-Z0-9_\-\.]{66}\b` | SendGrid API key |
| **Mailgun API Key** | `\bkey-[0-9a-f]{32}(?!\w)\b` | Mailgun API key |
| **NuGet API Key** | `\boy2[a-z0-9]{43}(?![a-z0-9])\b` | NuGet package manager API key |
| **JSON Web Token (JWT)** | `\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-\./+=]*\b` | Header + payload start with `eyJ` |
| **Private Key Header** | `-----BEGIN (?:[A-Z0-9_]+ )?PRIVATE KEY-----` | RSA, EC, OpenSSH, DSA, PGP |

---

## 3. Keyword Extraction on Words

| Type | Regex Pattern | Example Matches |
|---|---|---|
| **Generic API Key** | `(?i)(?:api[_-]?key\|apikey\|x-api-key)\s*[:=]\s*['"]([a-zA-Z0-9_\-+=\/\\]{16,64})['"]` | `api_key: 'abcdef1234567890...'` |
| **Generic Secret** | `(?i)(?:client[_-]?secret\|app[_-]?secret\|secret[_-]?key)\s*[:=]\s*['"]([a-zA-Z0-9_\-+=\/\\]{16,64})['"]` | `secret_key = "9823498234..."` |
| **Environment File (.env)** | `(?i)(?:DB_PASSWORD\|DATABASE_URL\|APP_KEY\|SECRET_KEY_BASE)\s*=\s*['"]?[^\r\n'"]+['"]?` | `DB_PASSWORD=RootSecret!` |
| **Database Connection URI** | `(?i)(?:mysql\|postgresql\|postgres\|mongodb(?:\+srv)?\|redis\|amqp):\/\/[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-@!#$%^&*()+=]+@[a-zA-Z0-9_.\-]+(?::\d+)?(?:\/[a-zA-Z0-9_.\-]*)?` | `postgres://user:pass@host/db` |
| **URL Query Parameter** | `(?i)[?&](?:api[_-]?key\|access_token\|auth_token\|secret)=([a-zA-Z0-9_\-\.]{16,})` | `?api_key=abcdef123456...` |
| **Authorization Header** | `(?i)^(?:Authorization:\s*Bearer\|X-Api-Key\|X-Auth-Token):\s*([a-zA-Z0-9_\-\.]{16,})` | `Authorization: Bearer ya29...` |

---

## 4. PII & Infrastructure Leaks

| Type | Regex Pattern | Notes |
|---|---|---|
| **Strict US SSN** | `\b(?!000\|666\|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b` | Excludes 000, 666, 900-999 area; 00 group; 0000 serial; mask: `***-**-1234` |
| **Internal IPv4 Address** | `(?<![0-9.])(?:10\.(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d)(?:\.(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d)){2}\|172\.(?:1[6-9]\|2\d\|3[0-1])(?:\.(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d)){2}\|192\.168(?:\.(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d)){2}\|127\.(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d)(?:\.(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d)){2}\|169\.254\.(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d)\.(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d))(?![0-9.])` | RFC 1918 (10/8, 172.16/12, 192.168/16), Loopback (127/8), Link-Local (169.254/16) |
| **Linux OS Server Path** | `/(?:etc/(?:passwd\|shadow\|hosts\|apache2\|nginx\|mysql\|php\|sudoers\|issue\|fstab|[a-zA-Z0-9_.-]+)\|var/(?:log\|www\|spool\|run\|lib\|cache)/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+\|home/[a-zA-Z0-9_.-]+/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+\|root/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+\|usr/(?:local\|share\|lib\|bin\|sbin)/(?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+\|opt/(?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+)` | Excludes static images/fonts (`.png`, `.css`) |
| **Windows OS Server Path** | `(?:[a-zA-Z]:\\(?:(?:inetpub\|Windows\|Users\|Program Files\|Program Files \(x86\)\|var\|app\|logs\|deployment\|www)[\a-zA-Z0-9_.-]*\|(?:[a-zA-Z0-9_.-]+[\\])+[a-zA-Z0-9_.-]+\.(?:exe\|dll\|cs\|vb\|config\|ini\|log\|aspx\|ashx\|php\|py\|jar\|xml\|json\|txt\|env))\|\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.-]+(?:\\[a-zA-Z0-9_.-]+)+)` | Windows paths & UNC shares |

---

## 5. Server & Database Error Signatures

| Category | Literal / String Signatures | Regex Signatures |
|---|---|---|
| **Apache** | `"Apache Server at"` | `AH[0-9]{5}:`, `mod_[\w]+:` |
| **Nginx** | `"client intended to address"`, `"could not build optimal proxy_headers_hash"` | - |
| **JBoss** | - | `JBWEB[0-9]{6}:`, `WFLY[A-Z0-9]+:` |
| **ASP.NET** | `"Exception of type"`, `"Microsoft OLE DB Provider"`, `"Server Error in '/' Application"` | `System\.([A-Za-z]{1,32}\.)*[A-Za-z]{0,32}Exception:`, `in [A-Za-z]:\\.*\.cs:line \d+` |
| **MySQL** | `"You have an error in your SQL syntax"`, `"Error: Unknown column"` | `SQL syntax.*MySQL`, `Warning.*mysql_` |
| **PostgreSQL** | `"PSQLException"`, `"unterminated quoted string at or near"` | `PostgreSQL.*ERROR`, `ERROR:\s+syntax error at or near` |
| **Oracle** | `"Oracle error"`, `"quoted string not properly terminated"` | `\bORA-[0-9]{5}\b`, `Oracle.*Driver\]` |
| **MSSQL** | `"Unclosed quotation mark"`, `"Microsoft SQL Native Client"` | `\[ODBC SQL Server Driver\]`, `Msg \d+, Level \d+, State \d+` |
| **SQLite** | `"[SQLITE_ERROR]"`, `"SQLiteException"` | `near ".*": syntax error`, `Warning.*sqlite_` |
| **PHP** | `"Fatal error:"`, `"Call to undefined function"` | `\.php on line [0-9]+`, `Fatal error:.*in /.*\.php.*line \d+` |
| **Java** | `".invoke(Unknown Source)"`, `"nested exception is"`, `"java.io.FileNotFoundException:"` | `\bat [a-zA-Z][a-zA-Z0-9_.]*\.[a-zA-Z][a-zA-Z0-9_]*\([^)]*\.java:\d+\)` |
| **Python** | `"Traceback (most recent call last):"`, `"NameError:"` | `File "[A-Za-z0-9\-_./]*", line [0-9]+, in` |
| **Ruby** | `"ActiveRecord::StatementInvalid"`, `"(backtrace)"` | `\.rb:[0-9]+:in` |
| **Node.js** | `"UnhandledPromiseRejectionWarning:"`, `"ReferenceError:"` | `\.js:[0-9]+:[0-9]+`, `Error:.*\n\s*at .* \([^)]*:\d+:\d+\)` |
| **Go** | `"panic: runtime error:"` | `goroutine \d+ \[.*\]:`, `panic:.*\n\s*goroutine \d+` |

---

## 6. Implementation Snippets

### Two-Stage Refiner in Java (Montoya API)
```java
public record RefinerRule(String name, Pattern primary, Pattern refiner, int lookback, boolean requireRefiner) {
    public List<String> findMatches(String text) {
        List<String> list = new ArrayList<>();
        Matcher m = primary.matcher(text);
        while (m.find()) {
            String val = m.group();
            if (refiner != null) {
                int start = Math.max(0, m.start() - lookback);
                Matcher pre = refiner.matcher(text);
                pre.region(start, m.start());
                if (pre.find()) val = pre.group() + val;
                else if (requireRefiner) continue;
            }
            list.add(val);
        }
        return list;
    }
}
```

### Quick Bambda Snippet (Burp HTTP History Filter)
```java
// Match any S3 bucket or Google/OpenAI API key in responses
String body = response.bodyToString();
boolean hasS3 = body.contains("s3.amazonaws.com") || body.contains("amazonaws.com");
boolean hasGoogle = Pattern.compile("\\bAIza[0-9A-Za-z\\-_]{35}\\b").matcher(body).find();
boolean hasOpenAI = Pattern.compile("\\bsk-[a-zA-Z0-9]{40,128}\\b").matcher(body).find();

if (hasS3 || hasGoogle || hasOpenAI) {
    String note = hasS3 ? "[S3 Bucket]" : (hasGoogle ? "[Google API Key]" : "[OpenAI Key]");
    String existing = requestResponse.annotations().notes();
    requestResponse.annotations().setNotes(existing == null || existing.isEmpty() ? note : existing + " | " + note);
    return true;
}
return false;
```
