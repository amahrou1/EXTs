package burp.jsendpointfinder;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EndpointStoreTest {

    @Test
    void loadMissingFileReturnsEmpty(@TempDir Path tmp) {
        EndpointStore store = new EndpointStore(tmp.resolve("does-not-exist.jsonl"), null);
        EndpointStore.LoadResult result = store.load();
        assertNotNull(result);
        assertTrue(result.records().isEmpty());
        assertTrue(result.dedupKeys().isEmpty());
    }

    @Test
    void saveThenLoadRoundTrip(@TempDir Path tmp) {
        Path file = tmp.resolve("endpoints.jsonl");
        EndpointStore store = new EndpointStore(file, null);

        LocalDateTime now = LocalDateTime.of(2026, 4, 11, 12, 0, 0);

        EndpointRecord a = new EndpointRecord(
                "/api/v1/users", "https://example.com/app.js",
                "200", now, "ctx a",
                EndpointType.API, false);

        EndpointRecord b = new EndpointRecord(
                "https://cdn.other.com/script.js", "https://example.com/app.js",
                "200", now, "ctx\tb\nmultiline\\slash",
                EndpointType.EXTERNAL, true);

        EndpointRecord c = new EndpointRecord(
                "/robots.txt", "https://example.com/app.js",
                "200", now, "ctx c",
                EndpointType.STATIC, false);

        List<EndpointRecord> in = new ArrayList<>();
        in.add(a);
        in.add(b);
        in.add(c);

        store.save(in);
        assertTrue(Files.exists(file));

        EndpointStore.LoadResult result = store.load();
        assertEquals(3, result.records().size());
        assertEquals(3, result.dedupKeys().size());

        EndpointRecord la = result.records().get(0);
        assertEquals("/api/v1/users", la.endpoint());
        assertEquals("https://example.com/app.js", la.sourceUrl());
        assertEquals("200", la.status());
        assertEquals(now, la.foundAt());
        assertEquals("ctx a", la.context());
        assertEquals(EndpointType.API, la.type());
        assertFalse(la.seen());

        EndpointRecord lb = result.records().get(1);
        assertEquals("https://cdn.other.com/script.js", lb.endpoint());
        assertEquals("ctx\tb\nmultiline\\slash", lb.context(),
                "tabs, newlines and backslashes should round-trip");
        assertEquals(EndpointType.EXTERNAL, lb.type());
        assertTrue(lb.seen());

        EndpointRecord lc = result.records().get(2);
        assertEquals("/robots.txt", lc.endpoint());
        assertEquals(EndpointType.STATIC, lc.type());

        assertTrue(result.dedupKeys().contains("/api/v1/users"));
        assertTrue(result.dedupKeys().contains("https://cdn.other.com/script.js"));
        assertTrue(result.dedupKeys().contains("/robots.txt"));
    }

    @Test
    void saveOverwritesPreviousFile(@TempDir Path tmp) {
        Path file = tmp.resolve("endpoints.jsonl");
        EndpointStore store = new EndpointStore(file, null);

        LocalDateTime now = LocalDateTime.of(2026, 4, 11, 12, 0, 0);

        List<EndpointRecord> first = new ArrayList<>();
        first.add(new EndpointRecord("/a", "https://x.com", "200", now, "c", EndpointType.RELATIVE, false));
        first.add(new EndpointRecord("/b", "https://x.com", "200", now, "c", EndpointType.RELATIVE, false));
        store.save(first);

        List<EndpointRecord> second = new ArrayList<>();
        second.add(new EndpointRecord("/c", "https://x.com", "200", now, "c", EndpointType.RELATIVE, false));
        store.save(second);

        EndpointStore.LoadResult result = store.load();
        assertEquals(1, result.records().size());
        assertEquals("/c", result.records().get(0).endpoint());
    }

    @Test
    void deleteFileRemovesStore(@TempDir Path tmp) {
        Path file = tmp.resolve("endpoints.jsonl");
        EndpointStore store = new EndpointStore(file, null);

        LocalDateTime now = LocalDateTime.now();
        List<EndpointRecord> in = new ArrayList<>();
        in.add(new EndpointRecord("/api/x", "https://x.com", "200", now, "c", EndpointType.API, false));
        store.save(in);
        assertTrue(Files.exists(file));

        store.deleteFile();
        assertFalse(Files.exists(file));

        EndpointStore.LoadResult result = store.load();
        assertTrue(result.records().isEmpty());
    }

    @Test
    void malformedLineIsSkipped(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("endpoints.jsonl");
        EndpointStore store = new EndpointStore(file, null);

        LocalDateTime now = LocalDateTime.of(2026, 4, 11, 12, 0, 0);
        List<EndpointRecord> in = new ArrayList<>();
        in.add(new EndpointRecord("/api/x", "https://x.com", "200", now, "c", EndpointType.API, false));
        store.save(in);

        // Append a garbage line
        Files.writeString(file, "garbage-no-tabs\n", java.nio.file.StandardOpenOption.APPEND);

        EndpointStore.LoadResult result = store.load();
        assertEquals(1, result.records().size());
        assertEquals("/api/x", result.records().get(0).endpoint());
    }
}
