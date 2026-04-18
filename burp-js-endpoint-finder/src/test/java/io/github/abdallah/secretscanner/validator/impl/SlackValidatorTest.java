package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SlackValidatorTest {

    private final SlackValidator validator = new SlackValidator();

    @Test
    void invalidAuthReturnsInvalid() {
        assertEquals(ValidationResult.INVALID,
                validator.parseResponse(200, "{\"ok\":false,\"error\":\"invalid_auth\"}"));
    }

    @Test
    void validAuthReturnsValid() {
        assertEquals(ValidationResult.VALID,
                validator.parseResponse(200, "{\"ok\":true,\"user\":\"U1234\"}"));
    }

    @Test
    void validWithWhitespace() {
        assertEquals(ValidationResult.VALID,
                validator.parseResponse(200, "{\"ok\" : true, \"user\": \"U1234\"}"));
    }

    @Test
    void nonTwoHundredUsesStatusMapping() {
        assertEquals(ValidationResult.INVALID,
                validator.parseResponse(401, ""));
        assertEquals(ValidationResult.RATE_LIMITED,
                validator.parseResponse(429, ""));
        assertEquals(ValidationResult.NETWORK_ERROR,
                validator.parseResponse(500, ""));
    }

    @Test
    void nullBodyTreatedAsInvalid() {
        assertEquals(ValidationResult.INVALID,
                validator.parseResponse(200, null));
    }
}
