package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

public final class SlackValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        var resp = post("https://slack.com/api/auth.test", "",
                "Authorization", "Bearer " + key,
                "Content-Type", "application/json");
        return parseResponse(resp.statusCode(), resp.body());
    }

    public ValidationResult parseResponse(int statusCode, String body) {
        if (statusCode == 200) {
            if (body != null && body.matches("(?s).*\"ok\"\\s*:\\s*true.*")) {
                return ValidationResult.VALID;
            }
            return ValidationResult.INVALID;
        }
        return fromStatus(statusCode);
    }
}
