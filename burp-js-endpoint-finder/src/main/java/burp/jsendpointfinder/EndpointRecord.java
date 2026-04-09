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

    public EndpointRecord(String endpoint, String sourceUrl, String status, LocalDateTime foundAt, String context) {
        this.endpoint = endpoint;
        this.sourceUrl = sourceUrl;
        this.status = status;
        this.foundAt = foundAt;
        this.context = context;
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
}
