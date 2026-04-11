package burp.jsendpointfinder;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class EndpointRecordTest {

    private static EndpointRecord rec(String endpoint, String sourceUrl) {
        return new EndpointRecord(endpoint, sourceUrl, "200", LocalDateTime.now(), "ctx");
    }

    @Test
    void typeApiDetectedForApiPath() {
        assertEquals(EndpointType.API,
                rec("/api/v1/users", "https://example.com/app.js").type());
    }

    @Test
    void typeApiDetectedForGraphqlPath() {
        assertEquals(EndpointType.API,
                rec("/graphql", "https://example.com/app.js").type());
    }

    @Test
    void typeApiDetectedForV2InAbsoluteUrl() {
        assertEquals(EndpointType.API,
                rec("https://example.com/v2/widgets", "https://example.com/app.js").type());
    }

    @Test
    void typeApiDetectedForOauth() {
        assertEquals(EndpointType.API,
                rec("/oauth/token", "https://example.com/app.js").type());
    }

    @Test
    void typeExternalDetectedWhenHostDiffers() {
        assertEquals(EndpointType.EXTERNAL,
                rec("https://cdn.other.com/thirdparty", "https://example.com/app.js").type());
    }

    @Test
    void typeExternalNotDetectedWhenSameHost() {
        assertNotEquals(EndpointType.EXTERNAL,
                rec("https://example.com/some/page", "https://example.com/app.js").type());
    }

    @Test
    void typeStaticDetectedForHtml() {
        assertEquals(EndpointType.STATIC,
                rec("/pages/home.html", "https://example.com/app.js").type());
    }

    @Test
    void typeStaticDetectedForJson() {
        assertEquals(EndpointType.STATIC,
                rec("/config/settings.json", "https://example.com/app.js").type());
    }

    @Test
    void typeStaticDetectedForXml() {
        assertEquals(EndpointType.STATIC,
                rec("/sitemap.xml", "https://example.com/app.js").type());
    }

    @Test
    void typeStaticDetectedForTxt() {
        assertEquals(EndpointType.STATIC,
                rec("/robots.txt", "https://example.com/app.js").type());
    }

    @Test
    void typeRelativeDetectedForPlainPath() {
        assertEquals(EndpointType.RELATIVE,
                rec("/dashboard/home", "https://example.com/app.js").type());
    }

    @Test
    void typeRelativeDetectedForRelativePath() {
        assertEquals(EndpointType.RELATIVE,
                rec("./utils/helper", "https://example.com/app.js").type());
    }

    @Test
    void markSeenFlipsSeenFlag() {
        EndpointRecord r = rec("/api/v1/users", "https://example.com/app.js");
        assertFalse(r.seen());
        r.markSeen();
        assertTrue(r.seen());
    }

    @Test
    void apiPrecedesExternalWhenBothWouldMatch() {
        // external host but /api/ in path -> API wins
        assertEquals(EndpointType.API,
                rec("https://other.com/api/v1/users", "https://example.com/app.js").type());
    }

    @Test
    void apiPrecedesStaticWhenBothWouldMatch() {
        // ends in .json but has /api/ in path -> API wins
        assertEquals(EndpointType.API,
                rec("/api/v1/config.json", "https://example.com/app.js").type());
    }
}
