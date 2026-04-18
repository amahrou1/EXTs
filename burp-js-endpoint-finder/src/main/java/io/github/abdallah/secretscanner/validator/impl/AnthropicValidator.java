package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

public final class AnthropicValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        var resp = get("https://api.anthropic.com/v1/models",
                "x-api-key", key,
                "anthropic-version", "2023-06-01");
        return fromStatus(resp.statusCode());
    }
}
