package io.github.abdallah.secretscanner.handler;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import io.github.abdallah.secretscanner.engine.SecretScanner;
import io.github.abdallah.secretscanner.model.Finding;
import io.github.abdallah.secretscanner.ui.SecretScannerTab;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;

public final class SecretScannerContextMenu implements ContextMenuItemsProvider {

    private final SecretScanner scanner;
    private final SecretScannerTab tab;
    private final ExecutorService executor;
    private final Set<String> seenIds;

    public SecretScannerContextMenu(SecretScanner scanner, SecretScannerTab tab,
                                    ExecutorService executor, Set<String> seenIds) {
        this.scanner  = scanner;
        this.tab      = tab;
        this.executor = executor;
        this.seenIds  = seenIds;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        JMenuItem item = new JMenuItem("Scan response(s) for secrets");
        item.addActionListener(e -> {
            List<HttpRequestResponse> selected = event.selectedRequestResponses();
            if (selected == null || selected.isEmpty()) {
                selected = event.messageEditorRequestResponse()
                        .map(ed -> List.of(ed.requestResponse()))
                        .orElse(List.of());
            }
            List<HttpRequestResponse> finalSel = selected;
            executor.submit(() -> scanItems(finalSel));
        });
        return List.of(item);
    }

    private void scanItems(List<HttpRequestResponse> items) {
        for (HttpRequestResponse rr : items) {
            try {
                if (rr.response() == null) continue;
                byte[] body = rr.response().body().getBytes();
                if (body == null || body.length == 0) continue;
                String ct = null;
                for (var h : rr.response().headers()) {
                    if (h.name().equalsIgnoreCase("Content-Type")) { ct = h.value(); break; }
                }
                if (SecretScanner.isBinaryContentType(ct)) continue;
                String url = rr.request() != null ? rr.request().url() : "unknown";
                String host = extractHost(url);
                List<Finding> findings = scanner.scan(body, host, url);
                for (Finding f : findings) {
                    if (seenIds.add(f.id())) tab.addFinding(f);
                }
            } catch (Throwable ignored) {}
        }
    }

    private String extractHost(String url) {
        if (url == null) return "";
        try {
            String h = new URI(url).getHost();
            return h != null ? h : "";
        } catch (Exception e) {
            return "";
        }
    }
}
