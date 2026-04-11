package burp.jsendpointfinder;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class EndpointRecord {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final String endpoint;
    private final String sourceUrl;
    private final String status;
    private final LocalDateTime foundAt;
    private final String context;
    private final EndpointType type;
    private volatile boolean seen;

    public EndpointRecord(String endpoint, String sourceUrl, String status, LocalDateTime foundAt, String context) {
        this(endpoint, sourceUrl, status, foundAt, context, EndpointType.compute(endpoint, sourceUrl), false);
    }

    public EndpointRecord(String endpoint, String sourceUrl, String status, LocalDateTime foundAt, String context,
                          EndpointType type, boolean seen) {
        this.endpoint = endpoint;
        this.sourceUrl = sourceUrl;
        this.status = status;
        this.foundAt = foundAt;
        this.context = context;
        this.type = type != null ? type : EndpointType.compute(endpoint, sourceUrl);
        this.seen = seen;
    }

    public String endpoint() {
        return endpoint;
    }

    public String sourceUrl() {
        return sourceUrl;
    }

    public String status() {
        return status;
    }

    public LocalDateTime foundAt() {
        return foundAt;
    }

    public String foundAtFormatted() {
        return foundAt.format(FORMATTER);
    }

    public String context() {
        return context;
    }

    public EndpointType type() {
        return type;
    }

    public EndpointType getType() {
        return type;
    }

    public boolean seen() {
        return seen;
    }

    public void markSeen() {
        this.seen = true;
    }

    public void setSeen(boolean seen) {
        this.seen = seen;
    }
}
