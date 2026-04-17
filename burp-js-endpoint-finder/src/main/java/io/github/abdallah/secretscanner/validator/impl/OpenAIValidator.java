package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

public final class OpenAIValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        var resp = get("https://api.openai.com/v1/models",
                "Authorization", "Bearer " + key);
        return fromStatus(resp.statusCode());
    }
}
