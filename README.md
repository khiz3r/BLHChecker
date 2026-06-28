# BLH Checker

A Burp Suite extension for detecting **Broken Link Hijacking** opportunities — dead external resources referenced in page markup that an attacker can claim to serve malicious content.

Java rewrite of [arbazkiraak/BurpBLH](https://github.com/arbazkiraak/BurpBLH) using the Montoya API.

---

## What it detects

| Type | How | Severity |
|------|-----|----------|
| Dead external links (4xx / 5xx) | HTTP status check | Medium |
| DNS-dead domains (NXDOMAIN) | Exception catch | Medium |
| Social media dead handles | Body fingerprint (platforms return 200 for deleted accounts) | Medium |
| Dead URL shortener services | Domain match (e.g. goo.gl shutdown) | Medium |

**Platforms fingerprinted:** Twitter/X, Instagram, Facebook, LinkedIn, GitHub, TikTok, YouTube

---

## How it works

- **Passive ScanCheck** — fires on Scanner queue traffic
- **HttpHandler** — fires on all in-scope proxy traffic (Proxy, Repeater, Intruder)
- Extracts URLs from `href`, `src`, `action`, `data`, `srcset`, `meta refresh`, `fetch()`, `import()`
- Deduplicates across the session — each URL is checked once
- Follows redirects (up to 5 hops), resolving `Location` relative to the current hop
- Skips noise domains (`google.com`, `cloudflare.com`, etc.) and private/loopback IPs
- Reports findings to the **Target tab** with response markers — use ← → arrows in the Response tab to step through each broken link in the page

---

## Requirements

- Burp Suite Professional (Montoya API)
- Java 17+

---

## Installation

1. Compile against the Montoya API JAR:
   ```bash
   javac -cp montoya-api.jar -d out BLHChecker.java
   jar cf BLHChecker.jar -C out .
   ```
2. In Burp: **Extensions → Add → Java → select `BLHChecker.jar`**
3. Add your target to Burp scope
4. Browse or run a passive scan — findings appear under **Target → Issues**

---

## Configuration

Edit the constants at the top of `BLHChecker.java`:

```java
private static final int     DEFAULT_THREADS       = 15;    // concurrent link checks
private static final int     DEFAULT_TIMEOUT_MS    = 5000;  // per-request timeout
private static final boolean DEFAULT_FOLLOW_REDIR  = true;  // chase redirects
private static final boolean DEFAULT_EXTERNAL_ONLY = true;  // skip same-origin links
private static final boolean DEFAULT_PROXY         = true;  // enable HttpHandler path
```

---

## Output

**Target tab** — issues grouped per page with each broken link listed, badged by type:

```
• [🟠 Social Dead]    https://twitter.com/oldhandle — twitter.com handle unclaimed
• [⚠ External]        https://old-cdn.example.com/widget.js — HTTP 404
• [🟠 Dead Shortener] https://goo.gl/xyz123 — Google URL Shortener (shut down March 2019)
```

**Extension output log** — one line per event:

```
[BLH] Loaded. ScanCheck + HttpHandler active.
[BLH] https://target.com/ — 18 link(s) extracted
[BLH] Found [MEDIUM]: https://old-cdn.example.com/widget.js
[BLH] BROKEN (404): https://old-cdn.example.com/widget.js
[BLH] Page done (proxy): https://target.com/ | reported 2 finding(s) to Target tab.
```

---

## Credits

Original Python extension: [arbazkiraak/BurpBLH](https://github.com/arbazkiraak/BurpBLH)