package io.github.abdallah.secretscanner.handler;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import io.github.abdallah.secretscanner.engine.SecretScanner;
import io.github.abdallah.secretscanner.model.Finding;
import io.github.abdallah.secretscanner.ui.SecretScannerTab;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;

public final class ResponseScanHandler implements HttpHandler {

    private final SecretScanner scanner;
    private final SecretScannerTab tab;
    private final ExecutorService executor;
    private final Set<String> seenIds;

    public ResponseScanHandler(SecretScanner scanner, SecretScannerTab tab,
                               ExecutorService executor, Set<String> seenIds) {
        this.scanner  = scanner;
        this.tab      = tab;
        this.executor = executor;
        this.seenIds  = seenIds;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent r) {
        return RequestToBeSentAction.continueWith(r);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!tab.isAutoScanEnabled()) {
            return ResponseReceivedAction.continueWith(response);
        }
        String ct = getContentType(response);
        if (SecretScanner.isBinaryContentType(ct)) {
            return ResponseReceivedAction.continueWith(response);
        }
        // Snapshot fields before submitting (Montoya objects may not be safe off-thread)
        byte[] bodyBytes;
        String host, url;
        try {
            bodyBytes = response.body().getBytes();
            host = response.initiatingRequest().headerValue("Host");
            if (host == null) host = extractHost(response.initiatingRequest().url());
            url = response.initiatingRequest().url();
        } catch (Throwable t) {
            return ResponseReceivedAction.continueWith(response);
        }
        final byte[] finalBody = bodyBytes;
        final String finalHost = host;
        final String finalUrl  = url;
        executor.submit(() -> {
            try {
                List<Finding> findings = scanner.scan(finalBody, finalHost, finalUrl);
                for (Finding f : findings) {
                    if (seenIds.add(f.id())) {
                        tab.addFinding(f);
                    }
                }
            } catch (Throwable ignored) {}
        });
        return ResponseReceivedAction.continueWith(response);
    }

    private String getContentType(HttpResponseReceived response) {
        try {
            for (var h : response.headers()) {
                if (h.name().equalsIgnoreCase("Content-Type")) return h.value();
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private String extractHost(String url) {
        if (url == null) return "";
        try {
            java.net.URI u = new java.net.URI(url);
            String h = u.getHost();
            return h != null ? h : "";
        } catch (Exception e) {
            return "";
        }
    }
}
