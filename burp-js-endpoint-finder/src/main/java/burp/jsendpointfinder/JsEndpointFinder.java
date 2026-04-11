package burp.jsendpointfinder;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class JsEndpointFinder implements BurpExtension {

    private static final long SAVE_DEBOUNCE_SECONDS = 2L;

    private ExecutorService executor;
    private ScheduledExecutorService scheduler;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JS Endpoint Finder");

        Set<String> globalDedup = ConcurrentHashMap.newKeySet();
        executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "JSEndpointFinder-worker");
            t.setDaemon(true);
            return t;
        });
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "JSEndpointFinder-save-scheduler");
            t.setDaemon(true);
            return t;
        });

        EndpointStore store = new EndpointStore(api.logging());

        EndpointTab tab = new EndpointTab(api, globalDedup, executor, store);

        // Load any persisted records BEFORE registering handlers so we don't race.
        EndpointStore.LoadResult loaded = store.load();
        if (loaded.dedupKeys() != null) {
            globalDedup.addAll(loaded.dedupKeys());
        }
        if (loaded.records() != null && !loaded.records().isEmpty()) {
            tab.loadRecords(loaded.records());
            api.logging().logToOutput(
                    "JS Endpoint Finder: loaded " + loaded.records().size() + " persisted endpoint(s).");
        }

        AtomicReference<ScheduledFuture<?>> pendingSave = new AtomicReference<>();
        Runnable saveTrigger = () -> {
            ScheduledFuture<?> prev = pendingSave.getAndSet(null);
            if (prev != null) {
                prev.cancel(false);
            }
            ScheduledFuture<?> next = scheduler.schedule(
                    () -> {
                        try {
                            store.save(tab.getTableModel().getAllRecords());
                        } catch (Throwable t) {
                            api.logging().logToError("Debounced save failed: " + t.getMessage());
                        }
                    },
                    SAVE_DEBOUNCE_SECONDS,
                    TimeUnit.SECONDS
            );
            pendingSave.set(next);
        };
        tab.setSaveTrigger(saveTrigger);

        api.http().registerHttpHandler(new EndpointHttpHandler(api, globalDedup, tab, executor));
        api.userInterface().registerContextMenuItemsProvider(new EndpointContextMenu(api, globalDedup, tab, executor));
        api.userInterface().registerSuiteTab("JS Endpoint Finder", tab.getPanel());

        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                try {
                    ScheduledFuture<?> prev = pendingSave.getAndSet(null);
                    if (prev != null) {
                        prev.cancel(false);
                    }
                    store.save(tab.getTableModel().getAllRecords());
                } catch (Throwable t) {
                    api.logging().logToError("Final save on unload failed: " + t.getMessage());
                }
                shutdown(executor);
                shutdown(scheduler);
                api.logging().logToOutput("JS Endpoint Finder unloaded.");
            }
        });

        api.logging().logToOutput("JS Endpoint Finder loaded — Community Edition compatible");
    }

    private static void shutdown(ExecutorService svc) {
        if (svc == null) {
            return;
        }
        svc.shutdownNow();
        try {
            svc.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
