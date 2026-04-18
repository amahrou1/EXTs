package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

public final class GitHubValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        var resp = get("https://api.github.com/user",
                "Authorization", "Bearer " + key,
                "Accept", "application/vnd.github+json",
                "User-Agent", "BurpSecretScanner/1.0");
        return fromStatus(resp.statusCode());
    }
}
