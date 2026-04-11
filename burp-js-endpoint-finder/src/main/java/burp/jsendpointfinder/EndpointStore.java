package burp.jsendpointfinder;

import burp.api.montoya.logging.Logging;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Persists endpoint records to disk so state survives Burp restarts.
 *
 * File format: one record per line, tab-separated, in this order:
 *   endpoint \t source \t status \t foundAt(ISO) \t context \t type \t seen
 *
 * Inside each field the following characters are escaped:
 *   \  -> \\
 *   \t -> \t   (literal backslash + t)
 *   \n -> \n
 *   \r -> \r
 *
 * Missing file, unreadable file, or malformed lines never throw: bad lines
 * are logged via Logging#logToError and skipped, and load() returns empty
 * collections on total failure.
 *
 * The extension uses the .jsonl extension by convention (one record per line),
 * even though the on-disk representation is TSV rather than JSON — this is
 * intentional so external tools treating ".jsonl" as "line-delimited records"
 * still work.
 */
public final class EndpointStore {

    public static final Path DEFAULT_STORAGE_DIR =
            Paths.get(System.getProperty("user.home"), ".burp-js-endpoint-finder");
    public static final Path DEFAULT_STORAGE_FILE =
            DEFAULT_STORAGE_DIR.resolve("endpoints.jsonl");

    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final Path file;
    private final Logging logging;

    public EndpointStore(Logging logging) {
        this(DEFAULT_STORAGE_FILE, logging);
    }

    public EndpointStore(Path file, Logging logging) {
        this.file = file;
        this.logging = logging;
    }

    public Path getFile() {
        return file;
    }

    public synchronized void save(List<EndpointRecord> records) {
        if (records == null) {
            return;
        }
        try {
            Path dir = file.getParent();
            if (dir != null) {
                Files.createDirectories(dir);
            }
            Path tmp = file.resolveSibling(file.getFileName().toString() + ".tmp");
            try (BufferedWriter w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                for (EndpointRecord r : records) {
                    w.write(serialize(r));
                    w.write('\n');
                }
            }
            try {
                Files.move(tmp, file,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            logError("Failed to save endpoint store: " + e.getMessage());
        } catch (Throwable t) {
            logError("Unexpected error saving endpoint store: " + t.getMessage());
        }
    }

    public synchronized LoadResult load() {
        List<EndpointRecord> records = new ArrayList<>();
        Set<String> keys = new HashSet<>();
        if (!Files.exists(file)) {
            return new LoadResult(records, keys);
        }
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            int lineNum = 0;
            while ((line = r.readLine()) != null) {
                lineNum++;
                if (line.isEmpty()) {
                    continue;
                }
                try {
                    EndpointRecord rec = parse(line);
                    if (rec != null) {
                        records.add(rec);
                        keys.add(rec.endpoint());
                    }
                } catch (Throwable t) {
                    logError("Skipping malformed endpoint store line " + lineNum + ": " + t.getMessage());
                }
            }
        } catch (IOException e) {
            logError("Failed to load endpoint store: " + e.getMessage());
            return new LoadResult(new ArrayList<>(), new HashSet<>());
        } catch (Throwable t) {
            logError("Unexpected error loading endpoint store: " + t.getMessage());
            return new LoadResult(new ArrayList<>(), new HashSet<>());
        }
        return new LoadResult(records, keys);
    }

    public synchronized void deleteFile() {
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            logError("Failed to delete endpoint store: " + e.getMessage());
        }
    }

    private static String serialize(EndpointRecord r) {
        StringBuilder sb = new StringBuilder();
        sb.append(escape(r.endpoint())).append('\t');
        sb.append(escape(r.sourceUrl())).append('\t');
        sb.append(escape(r.status())).append('\t');
        sb.append(escape(r.foundAt() != null ? r.foundAt().format(ISO) : "")).append('\t');
        sb.append(escape(r.context())).append('\t');
        sb.append(escape(r.type() != null ? r.type().name() : "RELATIVE")).append('\t');
        sb.append(r.seen() ? "1" : "0");
        return sb.toString();
    }

    private static EndpointRecord parse(String line) {
        String[] parts = line.split("\t", -1);
        if (parts.length < 7) {
            throw new IllegalArgumentException("expected 7 fields, got " + parts.length);
        }
        String endpoint = unescape(parts[0]);
        String source = unescape(parts[1]);
        String status = unescape(parts[2]);
        String foundAtRaw = unescape(parts[3]);
        String context = unescape(parts[4]);
        String typeRaw = unescape(parts[5]);
        boolean seen = "1".equals(parts[6]);

        LocalDateTime foundAt;
        try {
            foundAt = foundAtRaw == null || foundAtRaw.isEmpty()
                    ? LocalDateTime.now()
                    : LocalDateTime.parse(foundAtRaw, ISO);
        } catch (Exception e) {
            foundAt = LocalDateTime.now();
        }

        EndpointType type;
        try {
            type = EndpointType.valueOf(typeRaw);
        } catch (Exception e) {
            type = EndpointType.compute(endpoint, source);
        }

        return new EndpointRecord(endpoint, source, status, foundAt, context, type, seen);
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '\t' -> sb.append("\\t");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String unescape(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                switch (next) {
                    case '\\' -> sb.append('\\');
                    case 't' -> sb.append('\t');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    default -> {
                        sb.append(c);
                        sb.append(next);
                    }
                }
                i++;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private void logError(String msg) {
        if (logging != null) {
            try {
                logging.logToError(msg);
            } catch (Throwable ignored) {
            }
        }
    }

    public record LoadResult(List<EndpointRecord> records, Set<String> dedupKeys) {
    }
}
