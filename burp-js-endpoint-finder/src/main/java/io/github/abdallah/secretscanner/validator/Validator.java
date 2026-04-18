package io.github.abdallah.secretscanner.validator;

import io.github.abdallah.secretscanner.model.ValidationResult;

import java.io.IOException;

public interface Validator {
    ValidationResult validate(String key) throws IOException;
}
