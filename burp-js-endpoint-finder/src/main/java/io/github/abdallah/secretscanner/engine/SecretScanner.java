package io.github.abdallah.secretscanner.engine;

import io.github.abdallah.secretscanner.model.Finding;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;

public final class SecretScanner {

    private static final int MAX_BODY_BYTES   = 5 * 1024 * 1024;
    private static final int CHUNK_SIZE       = 256 * 1024;
    private static final int CHUNK_OVERLAP    = 512;
    private static final int CONTEXT_WINDOW   = 200; // chars for contextKeywords check
    private static final int SNIPPET_RADIUS   = 80;  // chars each side for the context snippet

    private volatile List<Rule> rules;
    private volatile Set<String> globalStoplist;

    public SecretScanner(List<Rule> rules, Set<String> globalStoplist) {
        this.rules = List.copyOf(rules);
        this.globalStoplist = globalStoplist == null ? Set.of() : globalStoplist;
    }

    public void updateRules(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    public int ruleCount() {
        return rules.size();
    }

    public List<Finding> scan(byte[] bodyBytes, String host, String url) {
        if (bodyBytes == null || bodyBytes.length == 0) return List.of();
        int scanLen = Math.min(bodyBytes.length, MAX_BODY_BYTES);
        // Decode as ISO-8859-1 for byte-accurate offset preservation.
        String body = new String(bodyBytes, 0, scanLen, java.nio.charset.StandardCharsets.ISO_8859_1);
        return scanString(body, host, url);
    }

    private List<Finding> scanString(String body, String host, String url) {
        if (body.length() <= CHUNK_SIZE) {
            return applyRules(body, 0, host, url);
        }
        // Chunked scan for large bodies.
        List<Finding> all = new ArrayList<>();
        Set<String> seenIds = new java.util.HashSet<>();
        int offset = 0;
        while (offset < body.length()) {
            int end = Math.min(offset + CHUNK_SIZE, body.length());
            String chunk = body.substring(offset, end);
            List<Finding> chunk_findings = applyRules(chunk, offset, host, url);
            for (Finding f : chunk_findings) {
                if (seenIds.add(f.id())) all.add(f);
            }
            if (end == body.length()) break;
            offset = end - CHUNK_OVERLAP;
        }
        return all;
    }

    private List<Finding> applyRules(String chunk, int chunkOffset, String host, String url) {
        List<Finding> out = new ArrayList<>();
        for (Rule rule : rules) {
            try {
                Matcher m = rule.pattern().matcher(chunk);
                while (m.find()) {
                    String match = m.group();
                    int matchStart = m.start();
                    int globalOffset = chunkOffset + matchStart;

                    if (isStoplisted(match, rule)) continue;
                    if (rule.entropyMin() > 0 && Entropy.of(match) < rule.entropyMin()) continue;
                    if (!contextKeywordsPresent(chunk, matchStart, rule)) continue;

                    String ctx = buildContext(chunk, matchStart, m.end());
                    double entropy = Entropy.of(match);
                    out.add(new Finding(rule, host, url, match, ctx, entropy, globalOffset));
                }
            } catch (Throwable ignored) {
            }
        }
        return out;
    }

    private boolean isStoplisted(String match, Rule rule) {
        if (globalStoplist.contains(match)) return true;
        for (String entry : rule.stoplist()) {
            if (match.contains(entry) || entry.contains(match)) return true;
        }
        return false;
    }

    private boolean contextKeywordsPresent(String chunk, int matchStart, Rule rule) {
        List<String> keywords = rule.contextKeywords();
        if (keywords.isEmpty()) return true;
        if (!rule.contextRequired()) return true;
        int lo = Math.max(0, matchStart - CONTEXT_WINDOW);
        int hi = Math.min(chunk.length(), matchStart + CONTEXT_WINDOW);
        String window = chunk.substring(lo, hi).toLowerCase();
        for (String kw : keywords) {
            if (window.contains(kw.toLowerCase())) return true;
        }
        return false;
    }

    private String buildContext(String chunk, int matchStart, int matchEnd) {
        int lo = Math.max(0, matchStart - SNIPPET_RADIUS);
        int hi = Math.min(chunk.length(), matchEnd + SNIPPET_RADIUS);
        return chunk.substring(lo, hi).replaceAll("[\\r\\n]+", " ");
    }

    public static boolean isBinaryContentType(String contentType) {
        if (contentType == null) return false;
        String lower = contentType.toLowerCase();
        return lower.startsWith("image/")
                || lower.startsWith("video/")
                || lower.startsWith("audio/")
                || lower.startsWith("font/")
                || lower.contains("application/octet-stream")
                || lower.contains("application/pdf")
                || lower.contains("application/zip")
                || lower.contains("application/x-zip")
                || lower.contains("application/x-rar");
    }
}
