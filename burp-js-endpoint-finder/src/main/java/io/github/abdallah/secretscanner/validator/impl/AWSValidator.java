package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

/** AWS validation requires both access key and secret — not implementable with key alone. */
public final class AWSValidator extends HttpValidator {
    @Override
    public ValidationResult validate(String key) throws IOException {
        return ValidationResult.NOT_IMPLEMENTED;
    }
}
