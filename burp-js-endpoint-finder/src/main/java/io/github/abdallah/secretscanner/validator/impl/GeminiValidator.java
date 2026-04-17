package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

public final class GeminiValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        var resp = get("https://generativelanguage.googleapis.com/v1beta/models?key=" + key);
        int status = resp.statusCode();
        if (status == 200 && resp.body() != null && resp.body().contains("\"models\"")) {
            return ValidationResult.VALID;
        }
        return fromStatus(status);
    }
}
