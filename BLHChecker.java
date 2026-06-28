package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * BLH Checker — Broken Link Hijacking Scanner
 * Java rewrite of arbazkiraak's BurpBLH Python extension
 * Uses Montoya API
 *
 * Checks:
 * [1] Social media handle dead-page fingerprinting
 *     → Twitter/X, Instagram, Facebook, LinkedIn, GitHub, TikTok, YouTube
 *     → Social platforms return HTTP 200 even for deleted accounts
 * [2] Dead URL shortener service detection (goo.gl shutdown etc.)
 * [3] Generic external broken links (4xx/5xx, DNS dead)
 * [4] HttpHandler alongside ScanCheck — covers ALL proxy traffic
 *     including Repeater/Intruder, not just Scanner
 * [5] Noise domain auto-exclusion (large infra domains = no false positives)
 * [6] Target tab row highlighting via Annotations API
 *     HIGH  → RED, MEDIUM → ORANGE
 */
public class BLHChecker implements BurpExtension {

    private MontoyaApi api;
    private Logging    logging;

    // ── Config defaults ──────────────────────────────────────────────────────
    private static final int     DEFAULT_THREADS       = 15;
    private static final int     DEFAULT_TIMEOUT_MS    = 5000;
    private static final boolean DEFAULT_FOLLOW_REDIR  = true;
    private static final boolean DEFAULT_EXTERNAL_ONLY = true;
    private static final boolean DEFAULT_PROXY         = true;

    // ── MIME types to scan ───────────────────────────────────────────────────
    private static final Set<String> SCAN_MIME_TYPES = Set.of(
        "HTML", "Script", "CSS", "JSON", "text/plain", "Other text"
    );

    // ── Alive status codes ───────────────────────────────────────────────────
    // ALIVE_FINAL:    only 2xx — used when followRedirects=true
    // ALIVE_NO_CHASE: 2xx + 3xx — used when followRedirects=false
    private static final Set<Integer> ALIVE_FINAL    = Set.of(200, 201, 203, 204, 206);
    private static final Set<Integer> ALIVE_NO_CHASE = Set.of(200, 201, 203, 206, 301, 302, 303, 307, 308);

    private Set<Integer> getAliveCodes() {
        return cfgFollowRedir() ? ALIVE_FINAL : ALIVE_NO_CHASE;
    }

    // ── [5] Noise domains — always skip ─────────────────────────────────────
    // Social platforms intentionally excluded — handled by SOCIAL_FINGERPRINTS.
    private static final Set<String> NOISE_DOMAINS = Set.of(
        "google.com", "googleapis.com",
        "microsoft.com", "apple.com",
        "cloudflare.com", "amazonaws.com",
        "w3.org", "schema.org"
    );

    // ── [1] Social media dead-page fingerprints ──────────────────────────────
    // Social platforms return HTTP 200 even for deleted/unclaimed handles.
    private static final Map<String, String> SOCIAL_FINGERPRINTS = Map.ofEntries(
        Map.entry("twitter.com",   "This account doesn't exist"),
        Map.entry("x.com",         "This account doesn't exist"),
        Map.entry("instagram.com", "Sorry, this page isn't available"),
        Map.entry("facebook.com",  "content isn't available"),
        Map.entry("linkedin.com",  "Page not found"),
        Map.entry("github.com",    "Not Found"),
        Map.entry("tiktok.com",    "Couldn't find this account"),
        Map.entry("youtube.com",   "This channel doesn't exist")
    );

    // ── [2] Dead URL shortener services ──────────────────────────────────────
    private static final Map<String, String> DEAD_SHORTENERS = Map.of(
        "goo.gl", "Google URL Shortener (shut down March 2019)"
        // buff.ly / ow.ly removed — status uncertain, don't flag without verification
    );

    // Without this, "example.co.uk" → "co.uk" instead of "example.co.uk"
    private static final Set<String> CC_SLDS = Set.of(
        "co.uk", "co.in", "co.nz", "co.za", "co.jp", "co.kr", "co.id",
        "com.au", "com.br", "com.cn", "com.mx", "com.ar", "com.sg",
        "com.tr", "com.hk", "com.ph", "com.my", "net.au", "org.uk",
        "org.au", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk"
    );

    // ── Regex patterns ───────────────────────────────────────────────────────
    private static final Pattern LINK_PATTERN = Pattern.compile(
        "(?:href|src|action|data|url|poster|cite|longdesc|icon)" +
        "\\s*=\\s*['\"]([^'\"\\s>;,)]+)",
        Pattern.CASE_INSENSITIVE
    );

    // srcset="img.png 1x, img2.png 2x" → ["img.png", "img2.png"]
    private static final Pattern SRCSET_PATTERN = Pattern.compile(
        "srcset\\s*=\\s*['\"]([^'\"]+)['\"]",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern META_REFRESH_PATTERN = Pattern.compile(
        "<meta[^>]+http-equiv\\s*=\\s*['\"]refresh['\"][^>]+content\\s*=\\s*['\"]" +
        "[^;]*;\\s*url=([^'\"\\s>]+)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern JS_FETCH_PATTERN = Pattern.compile(
        "fetch\\(['\"]([^'\"]+)['\"]|import\\(['\"]([^'\"]+)['\"]",
        Pattern.CASE_INSENSITIVE
    );

    // ── Session-wide dedup ───────────────────────────────────────────────────
    private final Set<String> checkedUrls = ConcurrentHashMap.newKeySet();

    // Counters for logging
    private final AtomicInteger totalScanned = new AtomicInteger(0);
    private final AtomicInteger totalBroken  = new AtomicInteger(0);

    // ── Threading ─────────────────────────────────────────────────────────────
    // Bug fix: two separate pools to prevent executor starvation.
    // processResponse() runs on outerExecutor and submits analyzeUrl() tasks
    // to innerExecutor. Using a single pool caused deadlock when all threads
    // were blocked in processResponse() waiting for inner futures that could
    // never start.
    private volatile ExecutorService outerExecutor; // processResponse tasks (HttpHandler)
    private volatile ExecutorService innerExecutor; // analyzeUrl tasks (both paths)

    // ════════════════════════════════════════════════════════════════════════
    // Init
    // ════════════════════════════════════════════════════════════════════════

    @Override
    public void initialize(MontoyaApi api) {
        this.api     = api;
        this.logging = api.logging();

        api.extension().setName("BLH Checker");

        // Bug fix: separate pools — see field comment above
        outerExecutor = Executors.newFixedThreadPool(Math.max(2, DEFAULT_THREADS / 3));
        innerExecutor = Executors.newFixedThreadPool(DEFAULT_THREADS);

        api.scanner().registerPassiveScanCheck(new BLHScanCheck(), ScanCheckType.PER_REQUEST);
        api.http().registerHttpHandler(new BLHHttpHandler());

        api.extension().registerUnloadingHandler(() -> {
            outerExecutor.shutdownNow();
            innerExecutor.shutdownNow();
            logging.logToOutput("BLH Checker unloaded.");
        });

        logging.logToOutput("[BLH] Loaded. ScanCheck + HttpHandler active.");
    }

    // ════════════════════════════════════════════════════════════════════════
    // [4] HttpHandler — covers Proxy/Repeater/Intruder traffic
    // ════════════════════════════════════════════════════════════════════════

    private class BLHHttpHandler implements HttpHandler {

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
            return RequestToBeSentAction.continueWith(req);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
            if (!cfgProxy()) return ResponseReceivedAction.continueWith(resp);

            String url = resp.initiatingRequest().url();
            if (!api.scope().isInScope(url)) return ResponseReceivedAction.continueWith(resp);

            String mimeType = resp.mimeType().name();
            boolean mimeOk = SCAN_MIME_TYPES.stream()
                .anyMatch(m -> mimeType.toLowerCase().contains(m.toLowerCase()));
            if (!mimeOk) return ResponseReceivedAction.continueWith(resp);

            outerExecutor.submit(() -> processResponse(resp));

            return ResponseReceivedAction.continueWith(resp);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Passive Scan Check — covers Scanner queue
    // ════════════════════════════════════════════════════════════════════════

    private class BLHScanCheck implements PassiveScanCheck {

        @Override
        public String checkName() {
            return "BLH Checker — Broken Link Hijacking";
        }

        @Override
        public AuditResult doCheck(HttpRequestResponse rr) {
            if (!api.scope().isInScope(rr.request().url()))
                return AuditResult.auditResult(Collections.emptyList());

            HttpResponse response = rr.response();
            if (response == null) return AuditResult.auditResult(Collections.emptyList());

            String mimeType = response.mimeType().name();
            boolean mimeOk = SCAN_MIME_TYPES.stream()
                .anyMatch(m -> mimeType.toLowerCase().contains(m.toLowerCase()));
            if (!mimeOk) return AuditResult.auditResult(Collections.emptyList());

            String pageUrl  = rr.request().url();
            String baseHost = extractBaseHost(pageUrl);
            String body     = response.bodyToString();

            logging.logToOutput("[BLH] ScanCheck: " + pageUrl);

            List<String> candidates = extractLinks(body, baseHost, pageUrl);
            if (candidates.isEmpty()) return AuditResult.auditResult(Collections.emptyList());

            // Submit to innerExecutor directly (we're already off the scan thread)
            List<Future<BrokenLink>> futures = new ArrayList<>();
            for (String url : candidates) {
                if (cfgExternalOnly() && !isExternal(url, baseHost)) continue;
                if (checkedUrls.add(url)) {
                    totalScanned.incrementAndGet();
                    futures.add(innerExecutor.submit(() -> analyzeUrl(url, baseHost)));
                }
            }

            List<BrokenLink> brokenExternal = new ArrayList<>();
            List<BrokenLink> brokenInternal = new ArrayList<>();

            for (Future<BrokenLink> f : futures) {
                try {
                    BrokenLink bl = f.get(cfgTimeout() + 2000L, TimeUnit.MILLISECONDS);
                    if (bl != null) {
                        if (bl.severity() != AuditIssueSeverity.LOW)
                            totalBroken.incrementAndGet();
                        if (bl.isExternal) brokenExternal.add(bl);
                        else               brokenInternal.add(bl);
                        if (bl.severity() != AuditIssueSeverity.LOW)
                            logging.logToOutput("[BLH] Found [" + bl.severity() + "]: " + bl.url);
                    }
                } catch (TimeoutException | InterruptedException | ExecutionException e) {
                    // skip timed-out / errored checks
                }
            }

            logging.logToOutput("[BLH] Scan complete: " + totalScanned.get() + " checked, " + totalBroken.get() + " broken.");

            List<BrokenLink> toReport = brokenExternal.isEmpty() ? brokenInternal : brokenExternal;
            if (cfgExternalOnly()) toReport = brokenExternal;
            toReport = toReport.stream()
                .filter(bl -> bl.severity() != AuditIssueSeverity.LOW)
                .collect(java.util.stream.Collectors.toList());
            if (toReport.isEmpty()) return AuditResult.auditResult(Collections.emptyList());

            return AuditResult.auditResult(List.of(buildIssue(toReport, brokenExternal, brokenInternal, annotateRr(rr, toReport))));
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existing, AuditIssue newer) {
            // Deduplicate only on exact name + exact baseUrl (same issue on same page).
            // Removed same-root-domain branch — it was suppressing distinct findings on
            // different pages of the same domain (e.g. shop.example.com vs blog.example.com).
            if (existing.name().equals(newer.name()) &&
                existing.baseUrl().equals(newer.baseUrl()))
                return ConsolidationAction.KEEP_EXISTING;

            return ConsolidationAction.KEEP_BOTH;
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Core analysis — HttpHandler path (Proxy/Repeater/Intruder)
    // ════════════════════════════════════════════════════════════════════════

    private void processResponse(HttpResponseReceived resp) {
        String pageUrl  = resp.initiatingRequest().url();
        String baseHost = extractBaseHost(pageUrl);
        String body     = resp.bodyToString();

        List<String> candidates = extractLinks(body, baseHost, pageUrl);
        logging.logToOutput("[BLH] " + pageUrl + " — " + candidates.size() + " link(s) extracted");

        // Submit to innerExecutor — processResponse itself is already on outerExecutor,
        // so this never competes for the same pool (fixes starvation bug).
        List<Future<BrokenLink>> futures = new ArrayList<>();
        for (String url : candidates) {
            if (cfgExternalOnly() && !isExternal(url, baseHost)) continue;
            if (checkedUrls.add(url)) {
                totalScanned.incrementAndGet();
                futures.add(innerExecutor.submit(() -> analyzeUrl(url, baseHost)));
            }
        }

        List<BrokenLink> brokenExternal = new ArrayList<>();
        List<BrokenLink> brokenInternal = new ArrayList<>();

        for (Future<BrokenLink> f : futures) {
            try {
                BrokenLink bl = f.get(cfgTimeout() + 2000L, TimeUnit.MILLISECONDS);
                if (bl != null) {
                    if (bl.isExternal) brokenExternal.add(bl);
                    else               brokenInternal.add(bl);
                    if (bl.severity() != AuditIssueSeverity.LOW)
                        logging.logToOutput("[BLH] Found (proxy) [" + bl.severity() + "]: " + bl.url);
                }
            } catch (TimeoutException | InterruptedException | ExecutionException e) {
                // skip
            }
        }

        List<BrokenLink> toReport = brokenExternal.isEmpty() ? brokenInternal : brokenExternal;
        if (cfgExternalOnly()) toReport = brokenExternal;
        toReport = toReport.stream()
            .filter(bl -> bl.severity() != AuditIssueSeverity.LOW)
            .collect(java.util.stream.Collectors.toList());

        if (toReport.isEmpty()) {
            logging.logToOutput("[BLH] Page done (proxy): " + pageUrl + " | no reportable findings.");
            return;
        }

        HttpRequestResponse rr = annotateRr(
            HttpRequestResponse.httpRequestResponse(resp.initiatingRequest(), resp),
            toReport);

        AuditIssue issue = buildIssue(toReport, brokenExternal, brokenInternal, rr);
        api.siteMap().add(issue);
        // Also add the annotated rr so the row itself gets highlighted
        api.siteMap().add(rr);

        totalBroken.addAndGet(toReport.size());
        logging.logToOutput("[BLH] Page done (proxy): " + pageUrl
            + " | reported " + toReport.size() + " finding(s) to Target tab.");
    }

    // ════════════════════════════════════════════════════════════════════════
    // BrokenLink result object
    // ════════════════════════════════════════════════════════════════════════

    private enum LinkStatus {
        BROKEN,
        SOCIAL_DEAD,
        DEAD_SHORTENER
    }

    private static class BrokenLink {
        final String     url;
        final boolean    isExternal;
        final LinkStatus status;
        final String     detail;

        BrokenLink(String url, boolean isExternal, LinkStatus status, String detail) {
            this.url        = url;
            this.isExternal = isExternal;
            this.status     = status;
            this.detail     = detail;
        }

        AuditIssueSeverity severity() {
            return switch (status) {
                case SOCIAL_DEAD    -> AuditIssueSeverity.MEDIUM;
                case DEAD_SHORTENER -> AuditIssueSeverity.MEDIUM;
                case BROKEN         -> isExternal ? AuditIssueSeverity.MEDIUM : AuditIssueSeverity.LOW;
            };
        }

        String badge() {
            return switch (status) {
                case SOCIAL_DEAD    -> "🟠 Social Dead";
                case DEAD_SHORTENER -> "🟠 Dead Shortener";
                case BROKEN         -> isExternal ? "⚠ External" : "Internal";
            };
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // URL Analysis pipeline
    // ════════════════════════════════════════════════════════════════════════

    private BrokenLink analyzeUrl(String urlStr, String baseHost) {
        String host       = null;
        String rootDomain = null;
        boolean external  = false;
        try {
            URI uri = new URI(urlStr);
            host = uri.getHost();
            if (host == null) return null;

            // Skip localhost and private/loopback targets
            if (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("::1")
                || host.startsWith("192.168.") || host.startsWith("10.")
                || host.matches("172\\.(1[6-9]|2[0-9]|3[01])\\..*")) return null;

            rootDomain = getRootDomain(host);
            external   = isExternal(urlStr, baseHost);

            // [5] Skip noise domains
            if (NOISE_DOMAINS.contains(rootDomain)) return null;

            // [2] Dead shortener — flag immediately without HTTP check
            if (DEAD_SHORTENERS.containsKey(rootDomain)) {
                return new BrokenLink(urlStr, external, LinkStatus.DEAD_SHORTENER,
                    DEAD_SHORTENERS.get(rootDomain));
            }

            // HTTP check
            HttpRequest req = HttpRequest.httpRequestFromUrl(urlStr);
            RequestOptions reqOpts = RequestOptions.requestOptions()
                .withResponseTimeout(cfgTimeout());
            HttpRequestResponse resp = api.http().sendRequest(req, reqOpts);
            if (resp == null || resp.response() == null) {
                if (!external) return null;
                return new BrokenLink(urlStr, external, LinkStatus.BROKEN, "Unreachable");
            }

            int status = resp.response().statusCode();
            String body = resp.response().bodyToString();

            // Follow redirects — resolve Location relative to current hop URL
            if (cfgFollowRedir()) {
                String currentUrl = urlStr;
                int hops = 0;
                while (isRedirect(status) && hops < 5) {
                    String loc = resp.response().headerValue("Location");
                    if (loc == null || loc.isBlank()) break;
                    try {
                        loc = new URI(loc).isAbsolute() ? loc : new URI(currentUrl).resolve(loc).toString();
                    } catch (URISyntaxException ex) {
                        break;
                    }
                    currentUrl = loc;
                    req  = HttpRequest.httpRequestFromUrl(loc);
                    resp = api.http().sendRequest(req, reqOpts);
                    if (resp == null || resp.response() == null) break;
                    status = resp.response().statusCode();
                    body   = resp.response().bodyToString();
                    hops++;
                }
            }

            // [1] Social handle check — platform returns 200 but page signals dead account
            String socialFingerprint = SOCIAL_FINGERPRINTS.get(rootDomain);
            if (socialFingerprint != null && body != null && body.contains(socialFingerprint)) {
                logging.logToOutput("[BLH] SOCIAL DEAD (" + rootDomain + "): " + urlStr);
                return new BrokenLink(urlStr, external, LinkStatus.SOCIAL_DEAD, rootDomain + " handle unclaimed");
            }

            // [3] Standard broken check
            if (!getAliveCodes().contains(status)) {
                logging.logToOutput("[BLH] BROKEN (" + status + "): " + urlStr);
                if (!external) return null;
                return new BrokenLink(urlStr, external, LinkStatus.BROKEN, "HTTP " + status);
            }

        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            boolean isDnsDead = msg.contains("UnknownHost") || msg.contains("NXDOMAIN")
                || msg.contains("nodename nor servname") || msg.contains("Name or service not known");
            if (isDnsDead) {
                logging.logToOutput("[BLH] DNS DEAD: " + urlStr);
                if (!external) return null;
                return new BrokenLink(urlStr, external, LinkStatus.BROKEN, "DNS: NXDOMAIN");
            }
            logging.logToOutput("[BLH] ERROR " + urlStr + ": " + msg);
            if (!external) return null;
            return new BrokenLink(urlStr, external, LinkStatus.BROKEN, "Exception: " + msg);
        }

        return null; // alive
    }

    private boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Link extraction
    // ════════════════════════════════════════════════════════════════════════

    private List<String> extractLinks(String body, String baseHost, String pageUrl) {
        Set<String> seen = new LinkedHashSet<>();

        Matcher m1 = LINK_PATTERN.matcher(body);
        while (m1.find()) {
            String n = normalizeUrl(m1.group(1).trim(), baseHost, pageUrl);
            if (n != null) seen.add(n);
        }

        Matcher ms = SRCSET_PATTERN.matcher(body);
        while (ms.find()) {
            for (String entry : ms.group(1).split(",")) {
                String urlPart = entry.trim().split("\\s+")[0];
                String n = normalizeUrl(urlPart, baseHost, pageUrl);
                if (n != null) seen.add(n);
            }
        }

        Matcher m2 = META_REFRESH_PATTERN.matcher(body);
        while (m2.find()) {
            String n = normalizeUrl(m2.group(1).trim(), baseHost, pageUrl);
            if (n != null) seen.add(n);
        }

        Matcher m3 = JS_FETCH_PATTERN.matcher(body);
        while (m3.find()) {
            String raw = m3.group(1) != null ? m3.group(1) : m3.group(2);
            if (raw != null) {
                String n = normalizeUrl(raw.trim(), baseHost, pageUrl);
                if (n != null) seen.add(n);
            }
        }

        return new ArrayList<>(seen);
    }

    private String normalizeUrl(String raw, String baseHost, String pageUrl) {
        if (raw == null || raw.isBlank() || raw.contains(" ") ||
            raw.startsWith("data:") || raw.startsWith("javascript:") ||
            raw.startsWith("#") || raw.startsWith("mailto:") ||
            raw.startsWith("tel:") || raw.startsWith("blob:")) return null;

        if (raw.startsWith("//"))      return "https:" + raw;
        if (raw.startsWith("https://") ||
            raw.startsWith("http://")) return raw;
        if (raw.startsWith("www."))    return "https://" + raw;
        if (raw.startsWith("/")) {
            // Bug fix: tightened path-as-host heuristic.
            // Old logic treated any /segment-with-a-dot/... as a protocol-relative URL,
            // causing e.g. /v2.0/api/endpoint → https://v2.0 (malformed host).
            // Now we require the first path segment to look like a real hostname:
            // must contain a dot AND the part before the dot must be 2+ chars,
            // AND no digit-only labels (rules out version strings like "v2.0").
            String firstSeg = raw.length() > 1 ? raw.substring(1).split("/")[0] : "";
            if (looksLikeHost(firstSeg)) return "https://" + raw.substring(1);
            return baseHost + raw;
        }

        // Relative paths: resolve against pageUrl
        try {
            URI base     = new URI(pageUrl);
            URI resolved = base.resolve(raw);
            if (resolved.getHost() != null) return resolved.toString();
        } catch (URISyntaxException | IllegalArgumentException e) {
            // ignore malformed
        }

        return null;
    }

    /** Returns true if s looks like a real hostname (e.g. "cdn.example.com") */
    private boolean looksLikeHost(String s) {
        if (s == null || !s.contains(".")) return false;
        String[] parts = s.split("\\.");
        for (String part : parts) {
            if (part.isEmpty()) return false;
            // reject purely numeric labels (e.g. "2" in "v2.0")
            if (part.matches("\\d+")) return false;
            // reject labels starting with a digit that look like versions (e.g. "2x", "800w")
            if (part.matches("\\d+[a-zA-Z]+")) return false;
        }
        return parts.length >= 2 && parts[0].length() >= 2;
    }

    // ── Shared annotation helper — used by both ScanCheck and HttpHandler paths ─
    // Applies a note and marks each broken link URL in the response body so
    // Burp's ← → arrows navigate between findings.
    // Offsets are into the full raw response string (headers + body) as required
    // by the Montoya API — using body-only offsets causes misalignment in Pretty/Raw view.
    private HttpRequestResponse annotateRr(HttpRequestResponse rr, List<BrokenLink> findings) {
        Annotations annotations = Annotations.annotations()
            .withNotes("[BLH] " + findings.size() + " broken link(s) found");

        // Build response markers — one per broken link URL found in the raw response
        List<Marker> markers = new ArrayList<>();
        if (rr.response() != null) {
            String rawResponse = rr.response().toString();
            for (BrokenLink bl : findings) {
                // Search for the URL itself in the raw response
                int idx = rawResponse.indexOf(bl.url);
                if (idx != -1) {
                    markers.add(Marker.marker(idx, idx + bl.url.length()));
                    continue;
                }
                // Fallback: search for just the path+host portion in case the full URL
                // isn't literally present (e.g. href="/path" expanded to absolute by us)
                try {
                    java.net.URI uri = new java.net.URI(bl.url);
                    String path = uri.getPath();
                    if (path != null && !path.isEmpty()) {
                        int pidx = rawResponse.indexOf(path);
                        if (pidx != -1)
                            markers.add(Marker.marker(pidx, pidx + path.length()));
                    }
                } catch (java.net.URISyntaxException ignored) {}
            }
        }

        HttpRequestResponse annotated = rr.withAnnotations(annotations);
        if (!markers.isEmpty())
            annotated = annotated.withResponseMarkers(markers);
        return annotated;
    }

    // ════════════════════════════════════════════════════════════════════════
    // Issue builder
    // ════════════════════════════════════════════════════════════════════════

    private AuditIssue buildIssue(List<BrokenLink> toReport,
                                   List<BrokenLink> external,
                                   List<BrokenLink> internal,
                                   HttpRequestResponse rr) {
        AuditIssueSeverity severity = highestSeverity(toReport);

        String issueName = switch (severity) {
            case MEDIUM -> "Broken Link Hijacking — External Dead Link";
            default     -> "Broken Link Hijacking — Internal Dead Link";
        };

        // Prefer external findings for the detail; fall back to full list
        String pageHost = extractBaseHost(rr.request().url());
        List<BrokenLink> detailLinks = external.stream()
            .filter(bl -> !bl.url.contains(pageHost))
            .collect(java.util.stream.Collectors.toList());
        if (detailLinks.isEmpty()) detailLinks = toReport;

        StringBuilder detail = new StringBuilder();
        detail.append("<b>Broken links found that may be hijackable:</b><br><br>");

        if (!detailLinks.isEmpty()) {
            boolean showingExternal = detailLinks != toReport || !external.isEmpty();
            detail.append("<b>").append(showingExternal ? "External" : "Same-origin").append(" broken links:</b><br>");
            for (BrokenLink bl : detailLinks)
                detail.append("• [").append(bl.badge()).append("] ")
                      .append(bl.url).append(" — ").append(bl.detail).append("<br>");
        }

        if (detailLinks == toReport && !internal.isEmpty()) {
            detail.append("<br><b>Same-origin broken links:</b><br>");
            for (BrokenLink bl : internal)
                detail.append("• ").append(bl.url).append(" — ").append(bl.detail).append("<br>");
        }

        detail.append("<br><b>Next steps:</b><br>");
        detail.append("• 🟠 Social dead handles: create the account to demonstrate impersonation<br>");
        detail.append("• 🟠 Dead shorteners: check if slug is reclaimable on the platform<br>");
        detail.append("• ⚠ External broken links: register the domain or claim the resource<br>");

        return AuditIssue.auditIssue(
            issueName,
            detail.toString(),
            "Remove or update all broken external links. Monitor third-party domains and services.",
            rr.request().url(),
            severity,
            AuditIssueConfidence.CERTAIN,
            null, null,
            severity,
            rr
        );
    }

    private AuditIssueSeverity highestSeverity(List<BrokenLink> links) {
        return links.stream()
            .map(BrokenLink::severity)
            .max(Comparator.comparingInt(s -> switch (s) {
                case MEDIUM -> 2;
                case LOW    -> 1;
                default     -> 0;
            }))
            .orElse(AuditIssueSeverity.LOW);
    }

    // ════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════

    private String extractBaseHost(String url) {
        try {
            URI uri = new URI(url);
            return uri.getScheme() + "://" + uri.getHost() +
                (uri.getPort() != -1 ? ":" + uri.getPort() : "");
        } catch (URISyntaxException e) { return url; }
    }

    private boolean isExternal(String url, String baseHost) {
        try {
            String urlHost  = new URI(url).getHost();
            String pageHost = new URI(baseHost).getHost();
            if (urlHost == null || pageHost == null) return true;
            return !getRootDomain(urlHost).equalsIgnoreCase(getRootDomain(pageHost));
        } catch (URISyntaxException e) { return true; }
    }

    /**
     * "shop.example.co.uk" → "example.co.uk"
     * "sub.example.com"    → "example.com"
     */
    private String getRootDomain(String host) {
        if (host == null || host.isBlank()) return host;
        String[] parts = host.split("\\.");
        if (parts.length < 2) return host;

        if (parts.length >= 3) {
            String possibleCcSld = parts[parts.length - 2] + "." + parts[parts.length - 1];
            if (CC_SLDS.contains(possibleCcSld))
                return parts[parts.length - 3] + "." + possibleCcSld;
        }

        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    // ── Config accessors — return hardcoded defaults directly (no UI) ────────
    private int     cfgThreads()      { return DEFAULT_THREADS; }
    private int     cfgTimeout()      { return DEFAULT_TIMEOUT_MS; }
    private boolean cfgFollowRedir()  { return DEFAULT_FOLLOW_REDIR; }
    private boolean cfgExternalOnly() { return DEFAULT_EXTERNAL_ONLY; }
    private boolean cfgProxy()        { return DEFAULT_PROXY; }
}