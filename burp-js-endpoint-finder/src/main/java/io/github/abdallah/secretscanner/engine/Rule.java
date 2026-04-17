package io.github.abdallah.secretscanner.engine;

import java.util.List;
import java.util.regex.Pattern;

public final class Rule {

    public enum Severity { CRITICAL, HIGH, MEDIUM, LOW }

    private final String id;
    private final String name;
    private final String rawRegex;
    private final Pattern pattern;
    private final Severity severity;
    private final double entropyMin;
    private final List<String> contextKeywords;
    private final boolean contextRequired;
    private final List<String> stoplist;
    private final String validatorId;

    public Rule(String id, String name, String rawRegex, Severity severity,
                double entropyMin, List<String> contextKeywords,
                boolean contextRequired, List<String> stoplist, String validatorId) {
        this.id = id;
        this.name = name;
        this.rawRegex = rawRegex;
        this.pattern = Pattern.compile(rawRegex);
        this.severity = severity;
        this.entropyMin = entropyMin;
        this.contextKeywords = contextKeywords == null ? List.of() : List.copyOf(contextKeywords);
        this.contextRequired = contextRequired;
        this.stoplist = stoplist == null ? List.of() : List.copyOf(stoplist);
        this.validatorId = validatorId;
    }

    public String id()                      { return id; }
    public String name()                    { return name; }
    public String rawRegex()                { return rawRegex; }
    public Pattern pattern()                { return pattern; }
    public Severity severity()              { return severity; }
    public double entropyMin()              { return entropyMin; }
    public List<String> contextKeywords()   { return contextKeywords; }
    public boolean contextRequired()        { return contextRequired; }
    public List<String> stoplist()          { return stoplist; }
    public String validatorId()             { return validatorId; }
}
