package io.github.abdallah.secretscanner;

import burp.api.montoya.MontoyaApi;
import io.github.abdallah.secretscanner.engine.RuleLoader;
import io.github.abdallah.secretscanner.engine.Rule;
import io.github.abdallah.secretscanner.engine.SecretScanner;
import io.github.abdallah.secretscanner.handler.ResponseScanHandler;
import io.github.abdallah.secretscanner.handler.SecretScannerContextMenu;
import io.github.abdallah.secretscanner.model.Finding;
import io.github.abdallah.secretscanner.ui.SecretScannerTab;
import io.github.abdallah.secretscanner.validator.ValidatorRegistry;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class SecretScannerExtension {

    private ExecutorService scanExecutor;
    private ScheduledExecutorService validatorExecutor;

    public void initialize(MontoyaApi api) {
        List<Rule> rules;
        Set<String> stoplist;
        try {
            rules    = RuleLoader.loadFromClasspath();
            stoplist = RuleLoader.loadStoplistFromClasspath();
        } catch (Exception e) {
            api.logging().logToError("Secret Scanner: failed to load rules — " + e.getMessage());
            return;
        }
        api.logging().logToOutput("Secret Scanner: loaded " + rules.size() + " rules.");

        SecretScanner scanner = new SecretScanner(rules, stoplist);
        ValidatorRegistry validators = new ValidatorRegistry();

        scanExecutor = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "secret-scanner-" + System.nanoTime());
            t.setDaemon(true);
            return t;
        });
        validatorExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "secret-validator");
            t.setDaemon(true);
            return t;
        });

        Set<String> seenIds = ConcurrentHashMap.newKeySet();

        SecretScannerTab tab = new SecretScannerTab(scanner, validators, validatorExecutor);

        ResponseScanHandler handler = new ResponseScanHandler(scanner, tab, scanExecutor, seenIds);
        SecretScannerContextMenu menu =
                new SecretScannerContextMenu(scanner, tab, scanExecutor, seenIds);

        api.http().registerHttpHandler(handler);
        api.userInterface().registerContextMenuItemsProvider(menu);
        api.userInterface().registerSuiteTab("Secret Scanner", tab.getPanel());

        api.extension().registerUnloadingHandler(() -> {
            shutdown(scanExecutor);
            shutdown(validatorExecutor);
            api.logging().logToOutput("Secret Scanner unloaded.");
        });

        api.logging().logToOutput("Secret Scanner ready.");
    }

    private static void shutdown(ExecutorService svc) {
        if (svc == null) return;
        svc.shutdownNow();
        try { svc.awaitTermination(3, TimeUnit.SECONDS); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
