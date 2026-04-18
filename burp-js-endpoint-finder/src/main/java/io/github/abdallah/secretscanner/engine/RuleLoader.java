package io.github.abdallah.secretscanner.engine;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.PatternSyntaxException;

/**
 * Loads rules from a JSON array on disk or from the classpath resource rules.json.
 * Hand-rolled parser — no external JSON dependency.
 */
public final class RuleLoader {

    private RuleLoader() {}

    public static List<Rule> loadFromClasspath() throws IOException {
        try (InputStream is = RuleLoader.class.getClassLoader()
                .getResourceAsStream("rules.json")) {
            if (is == null) throw new IOException("rules.json not found on classpath");
            String json = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            return parse(json);
        }
    }

    public static List<Rule> loadFromFile(Path path) throws IOException {
        String json = Files.readString(path, StandardCharsets.UTF_8);
        return parse(json);
    }

    public static Set<String> loadStoplistFromClasspath() throws IOException {
        try (InputStream is = RuleLoader.class.getClassLoader()
                .getResourceAsStream("stoplist.txt")) {
            if (is == null) return Set.of();
            String text = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            Set<String> out = new HashSet<>();
            for (String line : text.split("\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    out.add(trimmed);
                }
            }
            return out;
        }
    }

    // ── JSON parsing ─────────────────────────────────────────────────────────

    public static List<Rule> parse(String json) {
        List<Rule> rules = new ArrayList<>();
        List<String> objects = splitToObjects(json);
        for (String obj : objects) {
            try {
                rules.add(parseObject(obj));
            } catch (Exception e) {
                // skip malformed rules silently
            }
        }
        return rules;
    }

    private static Rule parseObject(String obj) {
        String id = requireString(obj, "id");
        String name = getStr(obj, "name", id);
        String rawRegex = requireString(obj, "regex");
        String severityStr = getStr(obj, "severity", "MEDIUM");
        double entropyMin = getDouble(obj, "entropyMin", 0.0);
        List<String> contextKeywords = getStrArray(obj, "contextKeywords");
        boolean contextRequired = getBool(obj, "contextRequired", false);
        List<String> stoplist = getStrArray(obj, "stoplist");
        String validator = getStr(obj, "validator", null);

        Rule.Severity severity;
        try {
            severity = Rule.Severity.valueOf(severityStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            severity = Rule.Severity.MEDIUM;
        }

        try {
            return new Rule(id, name, rawRegex, severity, entropyMin,
                    contextKeywords, contextRequired, stoplist, validator);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Bad regex for rule " + id + ": " + e.getMessage());
        }
    }

    private static String requireString(String obj, String key) {
        String val = getStr(obj, key, null);
        if (val == null) throw new IllegalArgumentException("Missing field: " + key);
        return val;
    }

    // ── Field extractors ─────────────────────────────────────────────────────

    static String getStr(String obj, String key, String def) {
        int ki = obj.indexOf("\"" + key + "\"");
        if (ki < 0) return def;
        int colon = obj.indexOf(':', ki + key.length() + 2);
        if (colon < 0) return def;
        int vs = colon + 1;
        while (vs < obj.length() && Character.isWhitespace(obj.charAt(vs))) vs++;
        if (vs >= obj.length() || obj.charAt(vs) != '"') return def;
        int end = readStringEnd(obj, vs + 1);
        if (end < 0) return def;
        return unescapeJson(obj.substring(vs + 1, end));
    }

    static double getDouble(String obj, String key, double def) {
        int ki = obj.indexOf("\"" + key + "\"");
        if (ki < 0) return def;
        int colon = obj.indexOf(':', ki + key.length() + 2);
        if (colon < 0) return def;
        int vs = colon + 1;
        while (vs < obj.length() && Character.isWhitespace(obj.charAt(vs))) vs++;
        int ve = vs;
        while (ve < obj.length() && "-0123456789.eE+".indexOf(obj.charAt(ve)) >= 0) ve++;
        if (ve == vs) return def;
        try {
            return Double.parseDouble(obj.substring(vs, ve));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    static boolean getBool(String obj, String key, boolean def) {
        int ki = obj.indexOf("\"" + key + "\"");
        if (ki < 0) return def;
        int colon = obj.indexOf(':', ki + key.length() + 2);
        if (colon < 0) return def;
        int vs = colon + 1;
        while (vs < obj.length() && Character.isWhitespace(obj.charAt(vs))) vs++;
        if (obj.startsWith("true", vs)) return true;
        if (obj.startsWith("false", vs)) return false;
        return def;
    }

    static List<String> getStrArray(String obj, String key) {
        int ki = obj.indexOf("\"" + key + "\"");
        if (ki < 0) return List.of();
        int colon = obj.indexOf(':', ki + key.length() + 2);
        if (colon < 0) return List.of();
        int vs = colon + 1;
        while (vs < obj.length() && Character.isWhitespace(obj.charAt(vs))) vs++;
        if (vs >= obj.length() || obj.charAt(vs) != '[') return List.of();
        int end = findMatchingBracket(obj, vs);
        if (end < 0) return List.of();
        String contents = obj.substring(vs + 1, end);
        List<String> result = new ArrayList<>();
        int pos = 0;
        while (pos < contents.length()) {
            while (pos < contents.length() && Character.isWhitespace(contents.charAt(pos))) pos++;
            if (pos >= contents.length()) break;
            if (contents.charAt(pos) == '"') {
                int strEnd = readStringEnd(contents, pos + 1);
                if (strEnd < 0) break;
                result.add(unescapeJson(contents.substring(pos + 1, strEnd)));
                pos = strEnd + 1;
            } else {
                pos++;
            }
        }
        return result;
    }

    // Returns the index of the char AFTER the closing quote, or -1.
    // start is the index of the first char inside the string (after opening ").
    private static int readStringEnd(String s, int start) {
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') { i++; }
            else if (c == '"') return i;
        }
        return -1;
    }

    // Returns index of matching ] for [ at start, properly skipping strings.
    private static int findMatchingBracket(String s, int start) {
        int depth = 0;
        boolean inStr = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
            } else {
                if (c == '"') inStr = true;
                else if (c == '[') depth++;
                else if (c == ']') { depth--; if (depth == 0) return i; }
            }
        }
        return -1;
    }

    // Split the top-level JSON array into individual object strings.
    static List<String> splitToObjects(String json) {
        List<String> out = new ArrayList<>();
        boolean inStr = false;
        int depth = 0;
        int objStart = -1;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inStr) {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
            } else {
                if (c == '"') inStr = true;
                else if (c == '{') {
                    if (depth == 0) objStart = i;
                    depth++;
                } else if (c == '}') {
                    depth--;
                    if (depth == 0 && objStart >= 0) {
                        out.add(json.substring(objStart, i + 1));
                        objStart = -1;
                    }
                }
            }
        }
        return out;
    }

    public static String unescapeJson(String s) {
        if (s.indexOf('\\') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                sb.append(c);
                continue;
            }
            char next = s.charAt(++i);
            switch (next) {
                case '"'  -> sb.append('"');
                case '\\' -> sb.append('\\');
                case '/'  -> sb.append('/');
                case 'n'  -> sb.append('\n');
                case 'r'  -> sb.append('\r');
                case 't'  -> sb.append('\t');
                case 'b'  -> sb.append('\b');
                case 'f'  -> sb.append('\f');
                case 'u'  -> {
                    if (i + 4 < s.length()) {
                        sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                        i += 4;
                    }
                }
                default   -> { sb.append(c); sb.append(next); }
            }
        }
        return sb.toString();
    }
}
