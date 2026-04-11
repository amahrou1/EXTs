package burp.jsendpointfinder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class EndpointHttpHandler implements HttpHandler {

    private static final Pattern JS_CONTENT_TYPE = Pattern.compile(
            "(?i)javascript|ecmascript|application/json|text/json"
    );

    private static final Pattern HTML_CONTENT_TYPE = Pattern.compile(
            "(?i)text/html"
    );

    private static final Pattern JS_URL_EXTENSION = Pattern.compile(
            "(?i)\\.(?:js|mjs|cjs|jsx)(?:\\?.*)?$"
    );

    private static final Pattern JS_SENTINEL = Pattern.compile(
            "^\\s*(?:function\\s|var\\s|const\\s|let\\s|\\(function|!function|import\\s|export\\s)"
    );

    private static final Pattern SCRIPT_BLOCK = Pattern.compile(
            "<script[^>]*>([\\s\\S]*?)</script>",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern SCRIPT_SRC = Pattern.compile(
            "<script[^>]+src\\s*=\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE
    );

    private final MontoyaApi api;
    private final Set<String> globalDedup;
    private final EndpointTab tab;
    private final ExecutorService executor;

    public EndpointHttpHandler(MontoyaApi api, Set<String> globalDedup, EndpointTab tab, ExecutorService executor) {
        this.api = api;
        this.globalDedup = globalDedup;
        this.tab = tab;
        this.executor = executor;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        executor.submit(() -> {
            try {
                processResponse(response);
            } catch (Throwable t) {
                api.logging().logToError("Error processing response: " + t.getMessage());
            }
        });
        return ResponseReceivedAction.continueWith(response);
    }

    private void processResponse(HttpResponseReceived response) {
        String url = response.initiatingRequest().url();

        if (tab.isScopeOnly()) {
            try {
                if (!api.scope().isInScope(url)) {
                    return;
                }
            } catch (Throwable ignored) {
            }
        }

        HttpResponse httpResponse = response;
        String contentType = getContentType(httpResponse);
        String body = httpResponse.bodyToString();
        String statusCode = String.valueOf(httpResponse.statusCode());
        String urlPath = extractPath(url);

        boolean isJs = false;
        boolean isHtml = false;

        if (contentType != null) {
            if (JS_CONTENT_TYPE.matcher(contentType).find()) {
                isJs = true;
            } else if (HTML_CONTENT_TYPE.matcher(contentType).find()) {
                isHtml = true;
            }
        }

        if (!isJs && !isHtml && urlPath != null && JS_URL_EXTENSION.matcher(urlPath).find()) {
            isJs = true;
        }

        if (!isJs && !isHtml && body != null && !body.isEmpty() && contentType == null) {
            if (JS_SENTINEL.matcher(body).find()) {
                isJs = true;
            }
        }

        if (isJs && body != null && !body.isEmpty()) {
            scanBody(body, url, statusCode);
        } else if (isHtml && body != null && !body.isEmpty()) {
            processHtml(body, url, statusCode);
        }
    }

    private void processHtml(String body, String sourceUrl, String statusCode) {
        Matcher blockMatcher = SCRIPT_BLOCK.matcher(body);
        while (blockMatcher.find()) {
            String scriptContent = blockMatcher.group(1);
            if (scriptContent != null && !scriptContent.isBlank()) {
                scanBody(scriptContent, sourceUrl, "-");
            }
        }

        Matcher srcMatcher = SCRIPT_SRC.matcher(body);
        while (srcMatcher.find()) {
            String src = srcMatcher.group(1);
            if (src != null && !src.isEmpty()) {
                String resolved = UrlResolver.resolve(sourceUrl, src);
                String normalized = Filter.normalize(resolved);
                if (!Filter.shouldDrop(normalized, tab.getCustomExcludePattern()) && globalDedup.add(normalized)) {
                    EndpointRecord record = new EndpointRecord(
                            normalized, sourceUrl, statusCode,
                            LocalDateTime.now(),
                            "<script src=\"" + truncate(src, 100) + "\">"
                    );
                    tab.addRecord(record);
                    api.logging().logToOutput("[+] " + normalized + "  (from " + sourceUrl + ")");
                }
            }
        }
    }

    void scanBody(String body, String sourceUrl, String statusCode) {
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
    }

    private String getContentType(HttpResponse response) {
        try {
            if (response.headers() != null) {
                for (var header : response.headers()) {
                    if (header.name().equalsIgnoreCase("Content-Type")) {
                        return header.value();
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private String extractPath(String url) {
        if (url == null) {
            return null;
        }
        try {
            int queryIdx = url.indexOf('?');
            if (queryIdx >= 0) {
                return url.substring(0, queryIdx);
            }
            return url;
        } catch (Throwable t) {
            return url;
        }
    }

    private String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
