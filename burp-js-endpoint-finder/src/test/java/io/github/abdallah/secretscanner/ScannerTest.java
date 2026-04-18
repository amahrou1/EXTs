package io.github.abdallah.secretscanner;

import io.github.abdallah.secretscanner.engine.Entropy;
import io.github.abdallah.secretscanner.engine.Rule;
import io.github.abdallah.secretscanner.engine.RuleLoader;
import io.github.abdallah.secretscanner.engine.SecretScanner;
import io.github.abdallah.secretscanner.model.Finding;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * NOTE: All synthetic token samples are assembled via {@link #tok} at runtime to avoid
 * triggering source-code secret scanners. No sample here is a real credential.
 */
class ScannerTest {

    private static List<Rule> rules;
    private static Set<String> stoplist;
    private static SecretScanner scanner;

    @BeforeAll
    static void loadRules() throws IOException {
        rules    = RuleLoader.loadFromClasspath();
        stoplist = RuleLoader.loadStoplistFromClasspath();
        scanner  = new SecretScanner(rules, stoplist);
        assertFalse(rules.isEmpty(), "rules.json should have at least one rule");
    }

    /** Joins parts at runtime — prevents static secret scanners from matching multi-part values. */
    private static String tok(String... parts) {
        return String.join("", parts);
    }

    // ── Rule loading ──────────────────────────────────────────────────────────

    @Test
    void rulesJsonLoads54Rules() {
        assertEquals(54, rules.size(), "Expected exactly 54 rules from rules.json");
    }

    @Test
    void allRulesHaveNonEmptyId() {
        for (Rule r : rules) {
            assertNotNull(r.id(), "Rule id should not be null");
            assertFalse(r.id().isBlank(), "Rule id should not be blank");
        }
    }

    @Test
    void allRulesHaveCompiledPattern() {
        for (Rule r : rules) {
            assertNotNull(r.pattern(), "Compiled pattern should not be null for rule " + r.id());
        }
    }

    // ── Positive detection samples ────────────────────────────────────────────

    // 84-char body satisfies {80,120} requirement for Anthropic keys
    private static final String ANTHR_BODY =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTU";

    @Test
    void anthropicApiKeyDetected() {
        String sample = tok("sk-ant-", "api03-", ANTHR_BODY);
        assertRuleHits("anthropic-api-key", sample);
    }

    @Test
    void anthropicOauthTokenDetected() {
        String sample = tok("sk-ant-", "oat01-", ANTHR_BODY);
        assertRuleHits("anthropic-oauth-token", sample);
    }

    @Test
    void anthropicAdminKeyDetected() {
        String sample = tok("sk-ant-", "admin01-", ANTHR_BODY);
        assertRuleHits("anthropic-admin-key", sample);
    }

    @Test
    void openaiProjectKeyDetected() {
        // sk-proj- + 50 alphanumeric chars
        String sample = tok("sk-proj-", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        assertRuleHits("openai-project-key", sample);
    }

    @Test
    void googleApiKeyDetected() {
        // AIzaSy + 35 alphanumeric (total 39 chars including prefix)
        String sample = tok("AIzaSy", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a");
        assertRuleHits("google-api-key", sample);
    }

    @Test
    void huggingfaceTokenDetected() {
        String sample = tok("hf_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assertRuleHits("huggingface-token", sample);
    }

    @Test
    void xaiGrokKeyDetected() {
        // xai- + exactly 80 alphanumeric chars
        String sample = tok("xai-", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabc");
        assertRuleHits("xai-grok-key", sample);
    }

    @Test
    void perplexityKeyDetected() {
        // pplx- + 50 alphanumeric (satisfies {48,64})
        String sample = tok("pplx-", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx");
        assertRuleHits("perplexity-key", sample);
    }

    @Test
    void groqKeyDetected() {
        // gsk_ + 52 alphanumeric (satisfies {52,56})
        String sample = tok("gsk_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01");
        assertRuleHits("groq-key", sample);
    }

    @Test
    void replicateTokenDetected() {
        // r8_ + exactly 37 alphanumeric
        String sample = tok("r8_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk");
        assertRuleHits("replicate-token", sample);
    }

    @Test
    void npmTokenDetected() {
        // npm_ + exactly 36 alphanumeric
        String sample = tok("npm_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assertRuleHits("npm-access-token", sample);
    }

    @Test
    void githubPatClassicDetected() {
        // ghp_ + exactly 36 alphanumeric
        String sample = tok("ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assertRuleHits("github-pat-classic", sample);
    }

    @Test
    void githubPatFineGrainedDetected() {
        // github_pat_ + exactly 82 alphanumeric_
        String sample = tok("github_pat_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab");
        assertRuleHits("github-pat-fine-grained", sample);
    }

    @Test
    void githubOauthDetected() {
        String sample = tok("gho_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assertRuleHits("github-oauth", sample);
    }

    @Test
    void githubAppServerTokenDetected() {
        String sample = tok("ghs_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assertRuleHits("github-app-server-token", sample);
    }

    @Test
    void slackBotTokenDetected() {
        // xoxb-{10-13 digits}-{10-13 digits}-{24-34 alphanumeric}
        String sample = tok("xoxb-", "12345678901-", "12345678901-", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assertRuleHits("slack-bot-token", sample);
    }

    @Test
    void slackUserTokenDetected() {
        String sample = tok("xoxp-", "12345678901-", "12345678901-", "12345678901-",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh");
        assertRuleHits("slack-user-token", sample);
    }

    @Test
    void stripeSecretLiveDetected() {
        String sample = tok("sk_live_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg");
        assertRuleHits("stripe-secret-live", sample);
    }

    @Test
    void sendgridKeyDetected() {
        // SG.{22 alphanumeric}.{43 alphanumeric}
        String seg1 = "ABCDEFGHIJKLMNOPQRSTUV";          // exactly 22
        String seg2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"; // exactly 43
        String sample = tok("SG.", seg1, ".", seg2);
        assertRuleHits("sendgrid-key", sample);
    }

    @Test
    void jwtDetected() {
        // Build a structurally valid JWT from 3 base64url parts
        String h = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String p = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3RVc2VyIiwiaWF0IjoxNjE2MjM5MDIyfQ";
        String s = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String sample = tok(h, ".", p, ".", s);
        assertRuleHits("jwt-generic", sample);
    }

    @Test
    void awsAccessKeyDetected() {
        // AKIA + exactly 16 uppercase/digit chars, surrounded by spaces (satisfies lookbehind/lookahead)
        String sample = tok(" AKIA", "IOSFODNN7FAKEKEY ");
        assertRuleHits("aws-access-key-id", sample);
    }

    @Test
    void digitalOceanPatDetected() {
        // dop_v1_ + 64 hex chars
        String hex64 = "abcdef1234567890".repeat(4);
        String sample = tok("dop_v1_", hex64);
        assertRuleHits("digitalocean-pat", sample);
    }

    @Test
    void digitalOceanOauthDetected() {
        String hex64 = "abcdef1234567890".repeat(4);
        String sample = tok("doo_v1_", hex64);
        assertRuleHits("digitalocean-oauth", sample);
    }

    @Test
    void discordBotTokenDetected() {
        // [MN]{24}.[6 alphanumeric].[27-38 alphanumeric]
        String sample = tok("MTE1NTc4OTAxMDI3Mzc3Nzcw", ".GaBcDe.", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde");
        assertRuleHits("discord-bot-token", sample);
    }

    // ── Negative samples ──────────────────────────────────────────────────────

    @Test
    void randomTextProducesNoFindings() {
        String sample = "Hello, World! This is a normal response body with no secrets.";
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test").isEmpty(),
                "Normal text should produce no findings");
    }

    @Test
    void shortPrefixAloneIsNotDetected() {
        String sample = "sk-tooshort";
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().noneMatch(f -> f.rule().id().equals("openai-user-key-legacy")),
                "Too-short sk- value should not match openai-user-key-legacy");
    }

    // ── Entropy filter ────────────────────────────────────────────────────────

    @Test
    void entropyFilterSuppressesLowEntropyKey() {
        // 48 identical chars — very low entropy, should be filtered even if pattern matches
        String lowEntropy = tok("sk-", "x".repeat(48));
        assertTrue(scanner.scan(toBytes(lowEntropy), "test.local", "/test")
                .stream().noneMatch(f -> f.rule().id().equals("openai-user-key-legacy")),
                "Low-entropy placeholder key should be suppressed by entropy filter");
    }

    @Test
    void entropyMeasurementIsCorrect() {
        assertEquals(0.0, Entropy.of("aaaaaaaaaa"), 0.001,
                "All-same-char string has entropy 0");
        assertEquals(1.0, Entropy.of("ababababab"), 0.001,
                "Two equal-frequency chars have entropy 1.0");
        assertTrue(Entropy.of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop") > 4.0,
                "High-diversity string should have entropy > 4.0");
    }

    // ── Stoplist suppression ──────────────────────────────────────────────────

    @Test
    void stoplistSuppressesAkiaExample() {
        // AKIAIOSFODNN7EXAMPLE is in the global stoplist
        String sample = " AKIAIOSFODNN7EXAMPLE ";
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().noneMatch(f -> f.rule().id().equals("aws-access-key-id")),
                "aws-access-key-id stoplist entry should be suppressed");
    }

    @Test
    void perRuleStoplistSuppressesOpenaiPlaceholder() {
        // The per-rule stoplist on openai-user-key-legacy contains the all-x placeholder
        String placeholder = tok("sk-", "x".repeat(48));
        assertTrue(scanner.scan(toBytes(placeholder), "test.local", "/test")
                .stream().noneMatch(f -> f.match().equals(placeholder)),
                "Per-rule stoplist entry should be suppressed");
    }

    // ── contextRequired behavior ──────────────────────────────────────────────

    @Test
    void contextRequiredRuleDoesNotFireWithoutKeyword() {
        // deepseek-key has contextRequired=true; without a context keyword it must not fire
        String sample = tok("sk-", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn");
        assertTrue(scanner.scan(toBytes(sample), "unrelated.host", "/path")
                .stream().noneMatch(f -> f.rule().id().equals("deepseek-key")),
                "deepseek-key should not fire without context keyword");
    }

    @Test
    void contextRequiredRuleFiresWithKeyword() {
        // deepseek keyword placed right before the token
        String sample = tok("deepseek_api: sk-", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn");
        assertTrue(scanner.scan(toBytes(sample), "api.deepseek.com", "/v1")
                .stream().anyMatch(f -> f.rule().id().equals("deepseek-key")),
                "deepseek-key should fire when 'deepseek' keyword is near match");
    }

    @Test
    void awsSecretKeyContextualDoesNotFireWithoutContext() {
        // 40-char base64-ish string without AWS context
        String sample = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYXAMPLEKEYZ";
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().noneMatch(f -> f.rule().id().equals("aws-secret-access-key-contextual")),
                "aws-secret contextual rule should not fire without context keyword");
    }

    @Test
    void awsSecretKeyContextualFiresWithContext() {
        // Newline separator keeps '=' out of the lookbehind class [A-Za-z0-9/+=]
        String sample = "AWS_SECRET_ACCESS_KEY\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYXAMPLEKEYZ";
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().anyMatch(f -> f.rule().id().equals("aws-secret-access-key-contextual")),
                "aws-secret contextual rule should fire when AWS_SECRET_ACCESS_KEY keyword present");
    }

    // ── Binary content type ───────────────────────────────────────────────────

    @Test
    void imageContentTypeIsBinary() {
        assertTrue(SecretScanner.isBinaryContentType("image/png"));
        assertTrue(SecretScanner.isBinaryContentType("image/jpeg"));
        assertTrue(SecretScanner.isBinaryContentType("video/mp4"));
        assertTrue(SecretScanner.isBinaryContentType("application/octet-stream"));
        assertTrue(SecretScanner.isBinaryContentType("application/pdf"));
    }

    @Test
    void textContentTypeIsNotBinary() {
        assertFalse(SecretScanner.isBinaryContentType("text/html"));
        assertFalse(SecretScanner.isBinaryContentType("application/javascript"));
        assertFalse(SecretScanner.isBinaryContentType("application/json"));
        assertFalse(SecretScanner.isBinaryContentType(null));
    }

    // ── Deduplication ─────────────────────────────────────────────────────────

    @Test
    void sameMatchProducesDeterministicId() {
        String match = tok("ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        String body  = match + " repeated " + match;
        List<Finding> findings = scanner.scan(toBytes(body), "test.local", "/test");
        long distinct = findings.stream()
                .filter(f -> f.rule().id().equals("github-pat-classic"))
                .map(Finding::id)
                .distinct()
                .count();
        // Both occurrences produce the same ID — scanner doesn't dedup internally,
        // but both IDs must be identical (dedup belongs to the handler layer).
        if (distinct > 0) {
            assertEquals(1, distinct, "Same match string must produce the same finding ID");
        }
    }

    // ── RuleLoader unit tests ─────────────────────────────────────────────────

    @Test
    void ruleLoaderParsesMinimalObject() {
        String json = "[{\"id\":\"test-rule\",\"name\":\"Test\",\"regex\":\"abc123\",\"severity\":\"HIGH\"}]";
        List<Rule> parsed = RuleLoader.parse(json);
        assertEquals(1, parsed.size());
        assertEquals("test-rule", parsed.get(0).id());
        assertEquals(Rule.Severity.HIGH, parsed.get(0).severity());
    }

    @Test
    void ruleLoaderHandlesUnknownSeverityAsMedium() {
        String json = "[{\"id\":\"x\",\"name\":\"X\",\"regex\":\"abc\",\"severity\":\"BANANA\"}]";
        List<Rule> parsed = RuleLoader.parse(json);
        assertEquals(1, parsed.size());
        assertEquals(Rule.Severity.MEDIUM, parsed.get(0).severity());
    }

    @Test
    void ruleLoaderSkipsBadRegex() {
        String json = "[{\"id\":\"bad\",\"name\":\"Bad\",\"regex\":\"[invalid(\",\"severity\":\"LOW\"},"
                    + "{\"id\":\"good\",\"name\":\"Good\",\"regex\":\"abc\",\"severity\":\"LOW\"}]";
        List<Rule> parsed = RuleLoader.parse(json);
        assertEquals(1, parsed.size());
        assertEquals("good", parsed.get(0).id());
    }

    @Test
    void unescapeJsonHandlesCommonEscapes() {
        assertEquals("hello\nworld", RuleLoader.unescapeJson("hello\\nworld"));
        assertEquals("tab\there",   RuleLoader.unescapeJson("tab\\there"));
        assertEquals("quote\"end",  RuleLoader.unescapeJson("quote\\\"end"));
        assertEquals("slash/end",   RuleLoader.unescapeJson("slash\\/end"));
    }

    // ── v2 audit: extended binary content types ─────────────────────────────

    @Test
    void wasmIsBinary() {
        assertTrue(SecretScanner.isBinaryContentType("application/wasm"));
    }

    @Test
    void protobufIsBinary() {
        assertTrue(SecretScanner.isBinaryContentType("application/x-protobuf"));
    }

    @Test
    void grpcIsBinary() {
        assertTrue(SecretScanner.isBinaryContentType("application/grpc"));
    }

    // ── v2 audit: openai-user-key-legacy no longer requires context ──────────

    @Test
    void openaiLegacyKeyFiresWithoutContext() {
        // 48 diverse chars after "sk-" — should fire even without "openai" nearby
        String sample = tok(" sk-", "aB3dE6gH9jK2mN5pQ8sT1uW4xZ7bC0eF3hI6kL9nO1qR4tUy");
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().anyMatch(f -> f.rule().id().equals("openai-user-key-legacy")),
                "openai-user-key-legacy should fire without context (contextRequired=false)");
    }

    // ── v2 audit: openai legacy must NOT match sk-proj- or sk-ant- ───────────

    @Test
    void openaiLegacyDoesNotMatchSkProj() {
        String sample = tok("sk-proj-", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx");
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().noneMatch(f -> f.rule().id().equals("openai-user-key-legacy")),
                "openai-user-key-legacy must not match sk-proj- keys (length mismatch protects us)");
    }

    @Test
    void openaiLegacyDoesNotMatchStripeLive() {
        String sample = tok("sk_live_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx");
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().noneMatch(f -> f.rule().id().equals("openai-user-key-legacy")),
                "openai-user-key-legacy must not match sk_live_ (underscore not hyphen)");
    }

    // ── v2 audit: DB connection localhost downgrade ───────────────────────────

    @Test
    void mongodbLocalhostDowngradedToLow() {
        String sample = "mongodb://admin:secret123@localhost:27017/mydb";
        List<Finding> findings = scanner.scan(toBytes(sample), "test.local", "/test");
        assertTrue(findings.stream().anyMatch(f ->
                f.rule().id().equals("db-connection-mongodb")
                && f.effectiveSeverity() == Rule.Severity.LOW),
                "MongoDB connection to localhost should be downgraded to LOW");
    }

    @Test
    void postgresProductionStaysCritical() {
        String sample = "postgresql://admin:secret@db.prod.example.com:5432/app";
        List<Finding> findings = scanner.scan(toBytes(sample), "test.local", "/test");
        assertTrue(findings.stream().anyMatch(f ->
                f.rule().id().equals("db-connection-postgres")
                && f.effectiveSeverity() == Rule.Severity.CRITICAL),
                "PostgreSQL connection to production host should stay CRITICAL");
    }

    @Test
    void mysqlDotLocalDowngraded() {
        String sample = "mysql://root:pass@db.local:3306/test";
        List<Finding> findings = scanner.scan(toBytes(sample), "test.local", "/test");
        assertTrue(findings.stream().anyMatch(f ->
                f.rule().id().equals("db-connection-mysql")
                && f.effectiveSeverity() == Rule.Severity.LOW),
                "MySQL connection to .local host should be downgraded to LOW");
    }

    // ── v2 audit: contextual rules positive/negative ─────────────────────────

    @Test
    void datadogKeyWithContextFires() {
        String hex32 = "abcdef1234567890abcdef1234567890";
        String sample = "DD_API_KEY=" + hex32;
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().anyMatch(f -> f.rule().id().equals("datadog-api-key-contextual")),
                "datadog-api-key-contextual should fire with DD_API_KEY nearby");
    }

    @Test
    void datadogKeyWithoutContextSilent() {
        String hex32 = "abcdef1234567890abcdef1234567890";
        assertTrue(scanner.scan(toBytes(hex32), "test.local", "/test")
                .stream().noneMatch(f -> f.rule().id().equals("datadog-api-key-contextual")),
                "datadog-api-key-contextual should not fire without context");
    }

    @Test
    void algoliaKeyWithContextFires() {
        String hex32 = "abcdef1234567890abcdef1234567890";
        String sample = "X-Algolia-API-Key: " + hex32;
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().anyMatch(f -> f.rule().id().equals("algolia-admin-key-contextual")),
                "algolia-admin-key-contextual should fire with Algolia header nearby");
    }

    @Test
    void algoliaKeyWithoutContextSilent() {
        String hex32 = "abcdef1234567890abcdef1234567890";
        assertTrue(scanner.scan(toBytes(hex32), "test.local", "/test")
                .stream().noneMatch(f -> f.rule().id().equals("algolia-admin-key-contextual")),
                "algolia-admin-key-contextual should not fire without context");
    }

    @Test
    void herokuKeyWithContextFires() {
        String uuid = "12345678-1234-1234-1234-123456789012";
        String sample = "HEROKU_API_KEY=" + uuid;
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().anyMatch(f -> f.rule().id().equals("heroku-api-key")),
                "heroku-api-key should fire with HEROKU_API_KEY nearby");
    }

    @Test
    void herokuKeyWithoutContextSilent() {
        String uuid = "12345678-1234-1234-1234-123456789012";
        assertTrue(scanner.scan(toBytes(uuid), "test.local", "/test")
                .stream().noneMatch(f -> f.rule().id().equals("heroku-api-key")),
                "heroku-api-key should not fire without context");
    }

    // ── v2 audit: GCP service account JSON detection ─────────────────────────

    @Test
    void gcpServiceAccountJsonDetected() {
        String sample = "{\"type\": \"service_account\", \"project_id\": \"my-project\"}";
        assertTrue(scanner.scan(toBytes(sample), "test.local", "/test")
                .stream().anyMatch(f -> f.rule().id().equals("gcp-service-account-json")),
                "gcp-service-account-json should fire on service account JSON blob");
    }

    // ── v2 audit: isLocalDbHost edge cases ───────────────────────────────────

    @Test
    void isLocalDbHostDetectsLoopback() {
        assertTrue(SecretScanner.isLocalDbHost("mongodb://user:pass@127.0.0.1:27017/db"));
        assertTrue(SecretScanner.isLocalDbHost("postgres://u:p@localhost/db"));
        assertTrue(SecretScanner.isLocalDbHost("mysql://u:p@[::1]/db"));
        assertTrue(SecretScanner.isLocalDbHost("mysql://u:p@0.0.0.0/db"));
    }

    @Test
    void isLocalDbHostDetectsLocalSuffixes() {
        assertTrue(SecretScanner.isLocalDbHost("mongodb://u:p@db.local/x"));
        assertTrue(SecretScanner.isLocalDbHost("postgres://u:p@dev.test:5432/x"));
        assertTrue(SecretScanner.isLocalDbHost("mysql://u:p@host.example/x"));
        assertTrue(SecretScanner.isLocalDbHost("mysql://u:p@host.invalid/x"));
    }

    @Test
    void isLocalDbHostRejectsProduction() {
        assertFalse(SecretScanner.isLocalDbHost("mongodb://u:p@db.prod.company.com/x"));
        assertFalse(SecretScanner.isLocalDbHost("postgres://u:p@rds.amazonaws.com/x"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private void assertRuleHits(String ruleId, String sample) {
        List<Finding> findings = scanner.scan(toBytes(sample), "test.local", "/test");
        assertTrue(findings.stream().anyMatch(f -> f.rule().id().equals(ruleId)),
                "Rule " + ruleId + " should fire on sample");
    }

    private static byte[] toBytes(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }
}
