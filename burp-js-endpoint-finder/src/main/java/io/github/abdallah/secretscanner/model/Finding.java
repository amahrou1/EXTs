package io.github.abdallah.secretscanner.model;

import io.github.abdallah.secretscanner.engine.Rule;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class Finding {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final String id;
    private final Instant timestamp;
    private final Rule rule;
    private final String host;
    private final String url;
    private final String match;
    private final String context;
    private final double entropy;
    private final int bodyOffset;

    private volatile ValidationResult validationResult = ValidationResult.NOT_CHECKED;
    private volatile Instant validatedAt;

    public Finding(Rule rule, String host, String url,
                   String match, String context, double entropy, int bodyOffset) {
        this.id = sha256(rule.id() + ":" + match);
        this.timestamp = Instant.now();
        this.rule = rule;
        this.host = host;
        this.url = url;
        this.match = match;
        this.context = context;
        this.entropy = entropy;
        this.bodyOffset = bodyOffset;
    }

    // package-private constructor for deserialization
    Finding(String id, Instant timestamp, Rule rule, String host, String url,
            String match, String context, double entropy, int bodyOffset,
            ValidationResult validationResult, Instant validatedAt) {
        this.id = id;
        this.timestamp = timestamp;
        this.rule = rule;
        this.host = host;
        this.url = url;
        this.match = match;
        this.context = context;
        this.entropy = entropy;
        this.bodyOffset = bodyOffset;
        this.validationResult = validationResult;
        this.validatedAt = validatedAt;
    }

    public String id()                          { return id; }
    public Instant timestamp()                  { return timestamp; }
    public String timestampFormatted()          { return TS_FMT.format(timestamp); }
    public Rule rule()                          { return rule; }
    public String host()                        { return host; }
    public String url()                         { return url; }
    public String match()                       { return match; }
    public String matchTruncated()              { return match.length() > 60 ? match.substring(0, 57) + "..." : match; }
    public String context()                     { return context; }
    public double entropy()                     { return entropy; }
    public int bodyOffset()                     { return bodyOffset; }
    public ValidationResult validationResult()  { return validationResult; }
    public Instant validatedAt()                { return validatedAt; }

    public void setValidation(ValidationResult result, Instant when) {
        this.validationResult = result;
        this.validatedAt = when;
    }

    public static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return "[" + rule.severity() + "] " + rule.name() + " @ " + host + url;
    }
}
