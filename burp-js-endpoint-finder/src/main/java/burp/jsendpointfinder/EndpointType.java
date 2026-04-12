package burp.jsendpointfinder;

import java.net.URI;

public enum EndpointType {
    API,
    EXTERNAL,
    STATIC,
    RELATIVE,
    FRONTEND_ROUTE;

    static final String[] API_MARKERS = {
            "/api/",
            "/api-",
            "/apis/",
            "/v1/",
            "/v2/",
            "/v3/",
            "/v4/",
            "/v5/",
            "/graphql",
            "/gql",
            "/rest/",
            "/restapi/",
            "/jsonrpc",
            "/rpc/",
            "/oauth",
            "/oauth2/",
            "/auth/",
            "/authorize",
            "/token",
            "/sso/",
            "/saml/",
            "/.well-known/",
            "/webhook",
            "/webhooks/",
            "/callback",
            "/internal/",
            "/admin/api/",
            "/service/",
            "/services/"
    };

    private static final String[] STATIC_SUFFIXES = {
            ".html", ".json", ".xml", ".txt"
    };

    public static EndpointType compute(String endpoint, String sourceUrl) {
        if (endpoint == null || endpoint.isEmpty()) {
            return RELATIVE;
        }

        String lower = endpoint.toLowerCase();

        String pathForApiCheck = lower;
        if (hasScheme(lower)) {
            try {
                URI u = new URI(endpoint);
                String p = u.getRawPath();
                if (p != null) {
                    pathForApiCheck = p.toLowerCase();
                }
            } catch (Exception ignored) {
            }
        }
        for (String marker : API_MARKERS) {
            if (pathForApiCheck.contains(marker)) {
                return API;
            }
        }

        if (hasScheme(lower)) {
            String endpointHost = extractHost(endpoint);
            String sourceHost = extractHost(sourceUrl);
            if (endpointHost != null && sourceHost != null
                    && !endpointHost.equalsIgnoreCase(sourceHost)) {
                return EXTERNAL;
            }
            if (endpointHost != null && sourceHost == null) {
                return EXTERNAL;
            }
        }

        String trimmed = stripQueryAndFragment(lower);
        for (String ext : STATIC_SUFFIXES) {
            if (trimmed.endsWith(ext)) {
                return STATIC;
            }
        }

        return RELATIVE;
    }

    private static boolean hasScheme(String lower) {
        return lower.startsWith("http://") || lower.startsWith("https://");
    }

    private static String extractHost(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        try {
            URI u = new URI(url);
            return u.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private static String stripQueryAndFragment(String s) {
        int q = s.indexOf('?');
        if (q >= 0) {
            s = s.substring(0, q);
        }
        int h = s.indexOf('#');
        if (h >= 0) {
            s = s.substring(0, h);
        }
        return s;
    }
}
