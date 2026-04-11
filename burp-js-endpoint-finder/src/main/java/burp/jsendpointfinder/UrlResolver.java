package burp.jsendpointfinder;

import java.net.URI;

public final class UrlResolver {

    private UrlResolver() {
    }

    public static String resolve(String baseUrl, String relative) {
        if (relative == null) {
            return null;
        }
        if (relative.startsWith("http://") || relative.startsWith("https://") || relative.startsWith("//")) {
            return relative;
        }
        if (baseUrl == null || baseUrl.isEmpty()) {
            return relative;
        }
        try {
            URI base = new URI(baseUrl);
            return base.resolve(relative).toString();
        } catch (Throwable t) {
            return relative;
        }
    }

    public static String toAbsolute(String endpoint, String sourceUrl) {
        if (endpoint == null) {
            return null;
        }
        if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
            return endpoint;
        }
        if (endpoint.startsWith("//")) {
            return "https:" + endpoint;
        }
        return resolve(sourceUrl, endpoint);
    }
}
