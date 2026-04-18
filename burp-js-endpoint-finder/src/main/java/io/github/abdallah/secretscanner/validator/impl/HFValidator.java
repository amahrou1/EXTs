package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

public final class HFValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        var resp = get("https://huggingface.co/api/whoami-v2",
                "Authorization", "Bearer " + key);
        return fromStatus(resp.statusCode());
    }
}
