package burp.jsendpointfinder;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class JsEndpointFinder implements BurpExtension {

    private ExecutorService executor;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JS Endpoint Finder");

        Set<String> globalDedup = ConcurrentHashMap.newKeySet();
        executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "JSEndpointFinder-worker");
            t.setDaemon(true);
            return t;
        });

        EndpointTab tab = new EndpointTab(api, globalDedup);

        api.http().registerHttpHandler(new EndpointHttpHandler(api, globalDedup, tab, executor));
        api.userInterface().registerContextMenuItemsProvider(new EndpointContextMenu(api, globalDedup, tab, executor));
        api.userInterface().registerSuiteTab("JS Endpoint Finder", tab.getPanel());

        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                executor.shutdownNow();
                try {
                    executor.awaitTermination(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
                api.logging().logToOutput("JS Endpoint Finder unloaded.");
            }
        });

        api.logging().logToOutput("JS Endpoint Finder loaded — Community Edition compatible");
    }
}
