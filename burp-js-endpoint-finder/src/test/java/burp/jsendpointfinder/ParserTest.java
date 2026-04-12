package burp.jsendpointfinder;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ParserTest {

    @Test
    void testAbsolutePath() {
        List<String> result = Parser.extract("const url = \"/api/v1/users\";");
        assertTrue(result.contains("/api/v1/users"), "Should extract /api/v1/users, got: " + result);
    }

    @Test
    void testFullUrlWithAxios() {
        List<String> result = Parser.extract("axios.get(\"https://api.example.com/v2/data\")");
        assertTrue(result.contains("https://api.example.com/v2/data"), "Should extract full URL, got: " + result);
    }

    @Test
    void testFetchRelativePath() {
        List<String> result = Parser.extract("fetch(\"/graphql\")");
        assertTrue(result.contains("/graphql"), "Should extract /graphql, got: " + result);
    }

    @Test
    void testRelativeEndpoint() {
        List<String> result = Parser.extract("var x = \"users/profile.json\"");
        assertTrue(result.contains("users/profile.json"), "Should extract users/profile.json, got: " + result);
    }

    @Test
    void testStaticAssetFiltered() {
        List<String> result = Parser.extract("loadImage(\"logo.png\")");
        assertTrue(result.isEmpty(), "Should filter static asset logo.png, got: " + result);
    }

    @Test
    void testNoiseHostFiltered() {
        List<String> result = Parser.extract("\"https://w3.org\"");
        assertTrue(result.isEmpty(), "Should filter noise host w3.org, got: " + result);
    }

    @Test
    void testDeduplication() {
        List<String> result = Parser.extract("\"/api/users\"; \"/api/users\";");
        assertEquals(1, result.stream().filter(e -> e.equals("/api/users")).count(),
                "Should deduplicate /api/users, got: " + result);
    }

    @Test
    void testSourceMap() {
        List<String> result = Parser.extract("var x = 1;\n//# sourceMappingURL=app.js.map");
        assertTrue(result.contains("app.js.map"), "Should extract source map URL, got: " + result);
    }

    @Test
    void testEmptyBody() {
        List<String> result = Parser.extract("");
        assertTrue(result.isEmpty());
    }

    @Test
    void testNullBody() {
        List<String> result = Parser.extract(null);
        assertTrue(result.isEmpty());
    }

    @Test
    void testShortEndpointFiltered() {
        List<String> result = Parser.extract("var x = \"/ab\";");
        assertTrue(result.isEmpty(), "Should filter short endpoints, got: " + result);
    }

    @Test
    void testMixedEndpoints() {
        String body = """
                const API = "https://api.example.com/v1/users";
                fetch("/graphql");
                var config = "settings/app.json";
                //# sourceMappingURL=bundle.js.map
                """;
        List<String> result = Parser.extract(body);
        assertTrue(result.contains("https://api.example.com/v1/users"));
        assertTrue(result.contains("/graphql"));
        assertTrue(result.contains("settings/app.json"));
        assertTrue(result.contains("bundle.js.map"));
    }

    @Test
    void testCallPatternFetch() {
        List<String> result = Parser.extract("fetch('/api/data')");
        assertTrue(result.contains("/api/data"), "Should extract from fetch() call, got: " + result);
    }

    @Test
    void testCallPatternJqueryAjax() {
        List<String> result = Parser.extract("$.ajax(\"/api/submit\")");
        assertTrue(result.contains("/api/submit"), "Should extract from $.ajax() call, got: " + result);
    }

    @Test
    void testNoiseHostWithPathNotFiltered() {
        List<String> result = Parser.extract("\"https://fonts.googleapis.com/css2?family=Roboto\"");
        assertTrue(result.contains("https://fonts.googleapis.com/css2?family=Roboto"),
                "Should NOT filter noise host with a non-trivial path, got: " + result);
    }

    @Test
    void testCssExtensionFiltered() {
        List<String> result = Parser.extract("\"/styles/main.css\"");
        assertTrue(result.isEmpty(), "Should filter .css files, got: " + result);
    }

    @Test
    void testRelativePathWithDotSlash() {
        List<String> result = Parser.extract("import x from \"./utils/helper\"");
        assertTrue(result.contains("./utils/helper"), "Should extract ./utils/helper, got: " + result);
    }

    @Test
    void testRelativePathWithDotDotSlash() {
        List<String> result = Parser.extract("var t = \"../config/settings\"");
        assertTrue(result.contains("../config/settings"), "Should extract ../config/settings, got: " + result);
    }

    @Test
    void testBasePrefixJoin() {
        // Modern minified bundles split API URLs across .concat() calls. The
        // parser should recognise "/users" near a preceding "/api/v4/rooms/"
        // base prefix and surface BOTH the base prefix and the joined path.
        String body = "url:(0,o.Z)(n,\"/api/v4/rooms/\").concat(i,\"/users\")";
        List<String> result = Parser.extract(body);
        assertTrue(result.contains("/api/v4/rooms/"),
                "Should surface the base prefix /api/v4/rooms/, got: " + result);
        assertTrue(result.contains("/api/v4/rooms/users"),
                "Should surface the joined path /api/v4/rooms/users, got: " + result);
    }

    @Test
    void testFrontendRouteDetection() {
        // SPA router paths should be tagged as FRONTEND_ROUTE when the
        // surrounding context contains a hash-route include() check.
        String body = "case e.includes(\"#/reports/data-storage\"):r=t+\"/reports/data-storage\"";
        List<Parser.MatchResult> results = Parser.extractWithContext(body, null);
        Parser.MatchResult hit = null;
        for (Parser.MatchResult mr : results) {
            if ("/reports/data-storage".equals(mr.endpoint())) {
                hit = mr;
                break;
            }
        }
        assertNotNull(hit, "Should surface /reports/data-storage, got: " + results);
        assertEquals(EndpointType.FRONTEND_ROUTE, hit.type(),
                "Should be classified as FRONTEND_ROUTE, got type: " + hit.type());
    }

    @Test
    void testNoJoinForLongerPath() {
        // A 3-segment fragment already looks like a complete path and must
        // NOT be joined with a nearby base prefix.
        String body = "var a = \"/api/v4/\"; var b = \"/foo/bar/baz\";";
        List<String> result = Parser.extract(body);
        assertTrue(result.contains("/foo/bar/baz"),
                "Should surface the 3-segment fragment as-is, got: " + result);
        assertFalse(result.contains("/api/v4/foo/bar/baz"),
                "Should NOT join a 3-segment fragment, got: " + result);
    }

    @Test
    void testBasePrefixStandaloneNoFragment() {
        // A base prefix with no joinable fragment nearby should still be
        // surfaced as its own endpoint.
        String body = "const BASE = \"/api/v4/rooms/\";";
        List<String> result = Parser.extract(body);
        assertTrue(result.contains("/api/v4/rooms/"),
                "Base prefix should be surfaced standalone, got: " + result);
    }

    @Test
    void testDedupAfterJoin() {
        // Body has "/users" near "/api/v4/rooms/" (joins to "/api/v4/rooms/users")
        // AND a separate literal "/api/v4/rooms/users". Should produce only one row.
        String body = "url:(0,o.Z)(n,\"/api/v4/rooms/\").concat(i,\"/users\"); var x = \"/api/v4/rooms/users\";";
        List<String> result = Parser.extract(body);
        assertEquals(1, result.stream().filter(e -> e.equals("/api/v4/rooms/users")).count(),
                "Should deduplicate joined path, got: " + result);
    }

    @Test
    void testBasePrefixV1Join() {
        // The generalized regex should recognise /v1/ as a base prefix,
        // not just /api/.
        String body = "url:(0,o.Z)(n,\"/v1/rooms/\").concat(i,\"/users\")";
        List<String> result = Parser.extract(body);
        assertTrue(result.contains("/v1/rooms/"),
                "Should surface the /v1/ base prefix, got: " + result);
        assertTrue(result.contains("/v1/rooms/users"),
                "Should join fragment with /v1/ base, got: " + result);
    }

    @Test
    void testBasePrefixRestJoin() {
        // /rest/ is an API marker and should work as a base prefix.
        String body = "var base = \"/rest/items/\"; var sub = \"/details\";";
        List<String> result = Parser.extract(body);
        assertTrue(result.contains("/rest/items/"),
                "Should surface the /rest/ base prefix, got: " + result);
        assertTrue(result.contains("/rest/items/details"),
                "Should join fragment with /rest/ base, got: " + result);
    }

    @Test
    void testBasePrefixBacktickQuotes() {
        // Backtick-quoted base prefixes should be detected.
        String body = "const url = `/api/v2/config/`; var x = '/items';";
        List<String> result = Parser.extract(body);
        assertTrue(result.contains("/api/v2/config/"),
                "Should surface backtick-quoted base prefix, got: " + result);
    }
}
