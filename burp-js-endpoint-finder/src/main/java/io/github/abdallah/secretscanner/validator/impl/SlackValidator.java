package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

public final class SlackValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        var resp = post("https://slack.com/api/auth.test", "",
                "Authorization", "Bearer " + key,
                "Content-Type", "application/json");
        if (resp.statusCode() == 200 && resp.body() != null
                && resp.body().contains("\"ok\":true")) {
            return ValidationResult.VALID;
        }
        return resp.statusCode() == 200 ? ValidationResult.INVALID : fromStatus(resp.statusCode());
    }
}
