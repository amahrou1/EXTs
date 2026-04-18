package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;
import java.util.Base64;

public final class StripeValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        String encoded = Base64.getEncoder().encodeToString((key + ":").getBytes());
        var resp = get("https://api.stripe.com/v1/charges?limit=1",
                "Authorization", "Basic " + encoded);
        return fromStatus(resp.statusCode());
    }
}
