package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

public final class ReplicateValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        var resp = get("https://api.replicate.com/v1/account",
                "Authorization", "Bearer " + key);
        return fromStatus(resp.statusCode());
    }
}
