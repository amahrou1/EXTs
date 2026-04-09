package burp.jsendpointfinder;

import java.net.URI;
import java.util.Set;
import java.util.regex.Pattern;

public final class Filter {

    public static final Set<String> STATIC_ASSET_EXTENSIONS = Set.of(
            ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".woff", ".woff2", ".ttf", ".ico", ".map",
            ".mp4", ".webp", ".eot", ".otf"
    );

    public static final Set<String> NOISE_HOSTS = Set.of(
            "w3.org",
            "schema.org",
            "googletagmanager.com",
            "gstatic.com",
            "fonts.googleapis.com",
            "ajax.googleapis.com"
    );

    private static final int MIN_LENGTH = 4;

    private Filter() {
    }

    public static boolean shouldDrop(String endpoint, Pattern customExclude) {
        if (endpoint == null || endpoint.length() < MIN_LENGTH) {
            return true;
        }

        String lower = endpoint.toLowerCase();

        for (String ext : STATIC_ASSET_EXTENSIONS) {
            if (lower.endsWith(ext)) {
                return true;
            }
            int idx = lower.indexOf(ext + "?");
            if (idx >= 0) {
                return true;
            }
            int hashIdx = lower.indexOf(ext + "#");
            if (hashIdx >= 0) {
                return true;
            }
        }

        if (isNoiseHost(endpoint)) {
            return true;
        }

        if (customExclude != null) {
            try {
                if (customExclude.matcher(endpoint).find()) {
                    return true;
                }
            } catch (Exception ignored) {
            }
        }

        return false;
    }

    private static boolean isNoiseHost(String endpoint) {
        String hostPart = null;
        try {
            if (endpoint.startsWith("//")) {
                URI uri = new URI("https:" + endpoint);
                hostPart = uri.getHost();
                String path = uri.getPath();
                if (hostPart != null && NOISE_HOSTS.contains(hostPart.toLowerCase())) {
                    return path == null || path.isEmpty() || path.equals("/");
                }
            } else if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
                URI uri = new URI(endpoint);
                hostPart = uri.getHost();
                String path = uri.getPath();
                if (hostPart != null && NOISE_HOSTS.contains(hostPart.toLowerCase())) {
                    return path == null || path.isEmpty() || path.equals("/");
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    public static String normalize(String raw) {
        String s = raw.trim();
        while (s.length() > 0 && (s.charAt(0) == '"' || s.charAt(0) == '\'' || s.charAt(0) == '`')) {
            s = s.substring(1);
        }
        while (s.length() > 0) {
            char last = s.charAt(s.length() - 1);
            if (last == '"' || last == '\'' || last == '`') {
                s = s.substring(0, s.length() - 1);
            } else {
                break;
            }
        }
        s = s.trim();

        int schemeEnd = s.indexOf("://");
        if (schemeEnd > 0 && schemeEnd < 10) {
            int hostEnd = s.indexOf('/', schemeEnd + 3);
            if (hostEnd < 0) {
                return s.substring(0, schemeEnd).toLowerCase() + s.substring(schemeEnd, schemeEnd + 3) + s.substring(schemeEnd + 3).toLowerCase();
            }
            String schemePlusHost = s.substring(0, hostEnd).toLowerCase();
            String rest = s.substring(hostEnd);
            return schemePlusHost + rest;
        }

        if (s.startsWith("//") && s.length() > 2) {
            int hostEnd = s.indexOf('/', 2);
            if (hostEnd < 0) {
                return "//" + s.substring(2).toLowerCase();
            }
            String host = "//" + s.substring(2, hostEnd).toLowerCase();
            String rest = s.substring(hostEnd);
            return host + rest;
        }

        return s;
    }
}
