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

    private Parser() {
    }

    public static List<String> extract(String body) {
        return extract(body, null);
    }

    public static List<String> extract(String body, Pattern customExclude) {
        if (body == null || body.isEmpty()) {
            return List.of();
        }

        Set<String> seen = new LinkedHashSet<>();

        try {
            Matcher m = LINKFINDER_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    String normalized = Filter.normalize(raw);
                    if (!Filter.shouldDrop(normalized, customExclude)) {
                        seen.add(normalized);
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Matcher m = CALL_PATTERN_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    String normalized = Filter.normalize(raw);
                    if (!Filter.shouldDrop(normalized, customExclude)) {
                        seen.add(normalized);
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Matcher m = SOURCE_MAP_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    String normalized = Filter.normalize(raw);
                    if (normalized.length() >= 4) {
                        seen.add(normalized);
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        return new ArrayList<>(seen);
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

        try {
            Matcher m = LINKFINDER_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    String normalized = Filter.normalize(raw);
                    if (!Filter.shouldDrop(normalized, customExclude) && seen.add(normalized)) {
                        String ctx = buildContextSnippet(body, m.start(), m.end());
                        results.add(new MatchResult(normalized, ctx));
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Matcher m = CALL_PATTERN_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    String normalized = Filter.normalize(raw);
                    if (!Filter.shouldDrop(normalized, customExclude) && seen.add(normalized)) {
                        String ctx = buildContextSnippet(body, m.start(), m.end());
                        results.add(new MatchResult(normalized, ctx));
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            Matcher m = SOURCE_MAP_REGEX.matcher(body);
            while (m.find()) {
                String raw = m.group(1);
                if (raw != null && !raw.isEmpty()) {
                    String normalized = Filter.normalize(raw);
                    if (normalized.length() >= 4 && seen.add(normalized)) {
                        String ctx = buildContextSnippet(body, m.start(), m.end());
                        results.add(new MatchResult(normalized, ctx));
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        return results;
    }

    public static final class MatchResult {
        private final String endpoint;
        private final String context;

        public MatchResult(String endpoint, String context) {
            this.endpoint = endpoint;
            this.context = context;
        }

        public String endpoint() {
            return endpoint;
        }

        public String context() {
            return context;
        }
    }
}
