package burp.jsendpointfinder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;

public final class EndpointContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final Set<String> globalDedup;
    private final EndpointTab tab;
    private final ExecutorService executor;

    public EndpointContextMenu(MontoyaApi api, Set<String> globalDedup, EndpointTab tab, ExecutorService executor) {
        this.api = api;
        this.globalDedup = globalDedup;
        this.tab = tab;
        this.executor = executor;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        JMenuItem menuItem = new JMenuItem("Extract JS endpoints");
        menuItem.addActionListener(e -> {
            List<HttpRequestResponse> selected = event.selectedRequestResponses();
            if (selected == null || selected.isEmpty()) {
                selected = event.messageEditorRequestResponse()
                        .map(editor -> List.of(editor.requestResponse()))
                        .orElse(List.of());
            }
            List<HttpRequestResponse> finalSelected = selected;
            executor.submit(() -> processSelectedItems(finalSelected));
        });
        items.add(menuItem);
        return items;
    }

    private void processSelectedItems(List<HttpRequestResponse> items) {
        for (HttpRequestResponse reqResp : items) {
            try {
                if (reqResp.response() == null) {
                    continue;
                }
                String body = reqResp.response().bodyToString();
                if (body == null || body.isEmpty()) {
                    continue;
                }
                String sourceUrl = reqResp.request() != null ? reqResp.request().url() : "unknown";
                String statusCode = "-";
                try {
                    statusCode = String.valueOf(reqResp.response().statusCode());
                } catch (Throwable ignored) {
                }

                List<Parser.MatchResult> results = Parser.extractWithContext(body, tab.getCustomExcludePattern());
                for (Parser.MatchResult mr : results) {
                    if (globalDedup.add(mr.endpoint())) {
                        EndpointRecord record = new EndpointRecord(
                                mr.endpoint(), sourceUrl, statusCode,
                                LocalDateTime.now(), mr.context()
                        );
                        tab.addRecord(record);
                        api.logging().logToOutput("[+] " + mr.endpoint() + "  (from " + sourceUrl + ")");
                    }
                }
            } catch (Throwable t) {
                api.logging().logToError("Error in context menu scan: " + t.getMessage());
            }
        }
    }
}
