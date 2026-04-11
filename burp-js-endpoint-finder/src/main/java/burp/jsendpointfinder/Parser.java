package burp.jsendpointfinder;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Parser {

    static final Pattern LINKFINDER_REGEX = Pattern.compile(
            "(?:\"|')(" +
                    "((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})" +
                    "|" +
                    "((?:/|\\.\\./|\\./)[^\"'><,;| *()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})" +
                    "|" +
                    "([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))" +
                    "|" +
                    "([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^\"|']{0,}|))" +
                    ")(?:\"|')",
            Pattern.DOTALL
    );

    static final Pattern CALL_PATTERN_REGEX = Pattern.compile(
            "(?:fetch|axios(?:\\.(?:get|post|put|patch|delete|head))?|\\$\\.(?:get|post|ajax)|XMLHttpRequest\\(\\)\\.open)\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]"
    );

    static final Pattern SOURCE_MAP_REGEX = Pattern.compile(
            "//# sourceMappingURL=(.+?)\\s*$",
            Pattern.MULTILINE
    );

    /**
     * Matches a quoted /api/... string literal. Capture group 1 is the path
     * (without the surrounding quotes). Used by the base-prefix joining pass
     * in {@link #extractWithContext(String, Pattern)}.
     */
    static final Pattern BASE_PREFIX_REGEX = Pattern.compile(
            "[\"'](/api/[^\"']{1,200})[\"']"
    );

    private static final int MAX_JOIN_DISTANCE = 300;
    private static final int MAX_JOIN_SEGMENTS = 2;
    private static final int FRONTEND_ROUTE_CONTEXT = 100;

    private Parser() {
    }

    public static List<String> extract(String body) {
        return extract(body, null);
    }

    public static List<String> extract(String body, Pattern customExclude) {
        List<MatchResult> results = extractWithContext(body, customExclude);
        List<String> out = new ArrayList<>(results.size());
        for (MatchResult mr : results) {
            out.add(mr.endpoint());
        }
        return out;
    }

    public static String buildContextSnippet(String body, int matchStart, int matchEnd) {
        int beforeStart = Math.max(0, matchStart - 60);
        int afterEnd = Math.min(body.length(), matchEnd + 60);

        String before = body.substring(beforeStart, matchStart).replaceAll("[\\r\\n]+", " ");
        String match = body.substring(matchStart, matchEnd).replaceAll("[\\r\\n]+", " ");
        String after = body.substring(matchEnd, afterEnd).replaceAll("[\\r\\n]+", " ");

        if (before.length() > 60) {
            before = before.substring(before.length() - 60);
        }
        if (after.length() > 60) {
            after = after.substring(0, 60);
        }

        return before + match + after;
    }

    public static List<MatchResult> extractWithContext(String body, Pattern customExclude) {
        if (body == null || body.isEmpty()) {
            return List.of();
        }

        Set<String> seen = new LinkedHashSet<>();
        List<MatchResult> results = new ArrayList<>();

        // 1. Pre-scan the body for /api/... string literals — these act as
        //    base prefixes for fragments that the minifier split off.
        List<BasePrefix> basePrefixes = findBasePrefixes(body);

        // 2. LinkFinder pass: collect raw matches with their offsets so we
        //    can later walk backwards to find the nearest preceding prefix.
        List<LinkFinderHit> hits = new ArrayList<>();
        try {
            Matcher m = LINKFINDER_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    hits.add(new LinkFinderHit(raw, m.start(), m.end(), m.start(1)));
                }
            }
        } catch (Throwable ignored) {
        }

        // 3. For each LinkFinder hit, try to join it with a preceding base
        //    prefix when applicable, then filter/dedupe/classify.
        for (LinkFinderHit hit : hits) {
            String effective = maybeJoinWithBasePrefix(hit.raw, hit.contentStart, basePrefixes);
            if (effective == null) {
                effective = hit.raw;
            }
            String normalized = Filter.normalize(effective);
            if (Filter.shouldDrop(normalized, customExclude)) {
                continue;
            }
            if (!seen.add(normalized)) {
                continue;
            }
            String ctx = buildContextSnippet(body, hit.matchStart, hit.matchEnd);
            EndpointType type = detectFrontendRoute(body, hit.matchStart, normalized)
                    ? EndpointType.FRONTEND_ROUTE
                    : null;
            results.add(new MatchResult(normalized, ctx, type));
        }

        // 4. Inverse case: always surface the base prefix itself so the
        //    root /api/... path is findable even without a fragment to join.
        for (BasePrefix bp : basePrefixes) {
            String normalized = Filter.normalize(bp.prefix);
            if (Filter.shouldDrop(normalized, customExclude)) {
                continue;
            }
            if (!seen.add(normalized)) {
                continue;
            }
            String ctx = buildContextSnippet(body, bp.matchStart, bp.matchEnd);
            EndpointType type = detectFrontendRoute(body, bp.matchStart, normalized)
                    ? EndpointType.FRONTEND_ROUTE
                    : null;
            results.add(new MatchResult(normalized, ctx, type));
        }

        // 5. Call-pattern pass (fetch/axios/$.ajax/XHR.open) — unchanged
        //    semantics, but we now also apply frontend-route detection.
        try {
            Matcher m = CALL_PATTERN_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    String normalized = Filter.normalize(raw);
                    if (!Filter.shouldDrop(normalized, customExclude) && seen.add(normalized)) {
                        String ctx = buildContextSnippet(body, m.start(), m.end());
                        EndpointType type = detectFrontendRoute(body, m.start(), normalized)
                                ? EndpointType.FRONTEND_ROUTE
                                : null;
                        results.add(new MatchResult(normalized, ctx, type));
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        // 6. Source-map pass — unchanged, always bypasses the drop filter.
        try {
            Matcher m = SOURCE_MAP_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    String normalized = Filter.normalize(raw);
                    if (normalized.length() >= 4 && seen.add(normalized)) {
                        String ctx = buildContextSnippet(body, m.start(), m.end());
                        results.add(new MatchResult(normalized, ctx, null));
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        return results;
    }

    private static List<BasePrefix> findBasePrefixes(String body) {
        List<BasePrefix> out = new ArrayList<>();
        try {
            Matcher m = BASE_PREFIX_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    out.add(new BasePrefix(raw, m.start(), m.end(), m.start(1), m.end(1)));
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static String maybeJoinWithBasePrefix(String fragment, int fragmentOffset, List<BasePrefix> prefixes) {
        if (fragment == null || fragment.isEmpty()) {
            return null;
        }
        if (!fragment.startsWith("/")) {
            return null;
        }
        if (fragment.startsWith("/api/")) {
            return null;
        }
        if (countPathSegments(fragment) > MAX_JOIN_SEGMENTS) {
            return null;
        }
        BasePrefix nearest = null;
        int bestDistance = Integer.MAX_VALUE;
        for (BasePrefix bp : prefixes) {
            if (bp.contentEnd <= fragmentOffset) {
                int d = fragmentOffset - bp.contentEnd;
                if (d <= MAX_JOIN_DISTANCE && d < bestDistance) {
                    bestDistance = d;
                    nearest = bp;
                }
            }
        }
        if (nearest == null) {
            return null;
        }
        return joinPath(nearest.prefix, fragment);
    }

    private static String joinPath(String base, String fragment) {
        String b = base;
        if (!b.endsWith("/")) {
            b = b + "/";
        }
        String f = fragment;
        while (f.startsWith("/")) {
            f = f.substring(1);
        }
        return (b + f).replaceAll("//+", "/");
    }

    private static int countPathSegments(String path) {
        if (path == null || path.isEmpty()) {
            return 0;
        }
        String p = path;
        int q = p.indexOf('?');
        if (q >= 0) {
            p = p.substring(0, q);
        }
        int h = p.indexOf('#');
        if (h >= 0) {
            p = p.substring(0, h);
        }
        while (p.startsWith("/")) {
            p = p.substring(1);
        }
        while (p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        if (p.isEmpty()) {
            return 0;
        }
        int count = 0;
        for (String seg : p.split("/")) {
            if (!seg.isEmpty()) {
                count++;
            }
        }
        return count;
    }

    private static boolean detectFrontendRoute(String body, int matchStart, String endpoint) {
        if (endpoint != null && endpoint.startsWith("#/")) {
            return true;
        }
        if (body == null || matchStart <= 0) {
            return false;
        }
        int start = Math.max(0, matchStart - FRONTEND_ROUTE_CONTEXT);
        String pre;
        try {
            pre = body.substring(start, matchStart);
        } catch (Throwable t) {
            return false;
        }
        return pre.contains("e.includes(\"#/")
                || pre.contains("e.includes('#/")
                || pre.contains("router.push")
                || pre.contains("routerLink")
                || pre.contains("<Route ")
                || pre.contains("useNavigate")
                || pre.contains("history.push");
    }

    private static final class LinkFinderHit {
        final String raw;
        final int matchStart;
        final int matchEnd;
        final int contentStart;

        LinkFinderHit(String raw, int matchStart, int matchEnd, int contentStart) {
            this.raw = raw;
            this.matchStart = matchStart;
            this.matchEnd = matchEnd;
            this.contentStart = contentStart;
        }
    }

    private static final class BasePrefix {
        final String prefix;
        final int matchStart;
        final int matchEnd;
        final int contentStart;
        final int contentEnd;

        BasePrefix(String prefix, int matchStart, int matchEnd, int contentStart, int contentEnd) {
            this.prefix = prefix;
            this.matchStart = matchStart;
            this.matchEnd = matchEnd;
            this.contentStart = contentStart;
            this.contentEnd = contentEnd;
        }
    }

    public static final class MatchResult {
        private final String endpoint;
        private final String context;
        private final EndpointType type;

        public MatchResult(String endpoint, String context) {
            this(endpoint, context, null);
        }

        public MatchResult(String endpoint, String context, EndpointType type) {
            this.endpoint = endpoint;
            this.context = context;
            this.type = type;
        }

        public String endpoint() {
            return endpoint;
        }

        public String context() {
            return context;
        }

        public EndpointType type() {
            return type;
        }
    }
}
