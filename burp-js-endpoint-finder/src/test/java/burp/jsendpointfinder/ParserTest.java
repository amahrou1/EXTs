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
}
