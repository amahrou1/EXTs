# JS Endpoint Finder — Burp Suite Extension

A Burp Suite extension that extracts endpoints and URLs from JavaScript responses, inspired by [LinkFinder](https://github.com/GerbenJavado/LinkFinder). Fully compatible with **Burp Suite Community Edition**.

## Build

```bash
cd burp-js-endpoint-finder
mvn clean package
```

The compiled JAR lands at `target/js-endpoint-finder-1.0.jar`.

## Load in Burp

1. Open Burp Suite (Community or Professional).
2. Go to **Extensions → Installed → Add**.
3. Type: **Java**.
4. Select `target/js-endpoint-finder-1.0.jar`.
5. A new top-level tab called **JS Endpoint Finder** appears.

## How it works

JS Endpoint Finder registers an `HttpHandler` via `MontoyaApi.http().registerHttpHandler()` to intercept every HTTP response flowing through any Burp tool (Proxy, Repeater, Intruder, etc.) and a `ContextMenuItemsProvider` for on-demand scans via right-click. This is why it works on Community Edition — it does **not** use `IScannerCheck`, passive scan hooks, or the Scanner API, which are restricted to Professional. When a response is identified as JavaScript (by Content-Type, URL extension, or body sentinels) or HTML (for inline `<script>` extraction), the body is matched against the LinkFinder regex and supplementary call-pattern regexes to extract endpoints. Every extracted endpoint is normalized (trimmed, quotes stripped, scheme/host lowercased) and checked against a global `ConcurrentHashMap`-backed `Set<String>` for deduplication across the entire session. Only genuinely new endpoints are added to the results table and logged. All regex processing runs on a dedicated single-thread `ExecutorService` to avoid blocking Burp's HTTP pipeline.

## Features

- Automatic extraction from JS, JSON, and HTML responses
- On-demand extraction via right-click context menu
- Source map URL detection
- Live search/filter and custom exclude regex
- In-scope-only toggle
- Copy, export TXT, export JSON
- Zero external dependencies beyond the Montoya API
