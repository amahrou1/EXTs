package io.github.abdallah.secretscanner.validator.impl;

import io.github.abdallah.secretscanner.model.ValidationResult;
import io.github.abdallah.secretscanner.validator.Validator;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** Base class with a shared HttpClient and common response-to-result mapping. */
abstract class HttpValidator implements Validator {

    protected static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    protected static final Duration TIMEOUT = Duration.ofSeconds(10);

    protected HttpResponse<String> get(String url, String... headersKV) throws IOException {
        HttpRequest.Builder req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(TIMEOUT)
                .GET();
        for (int i = 0; i + 1 < headersKV.length; i += 2) {
            req.header(headersKV[i], headersKV[i + 1]);
        }
        try {
            return CLIENT.send(req.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
    }

    protected HttpResponse<String> post(String url, String body, String... headersKV) throws IOException {
        HttpRequest.Builder req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(TIMEOUT)
                .POST(HttpRequest.BodyPublishers.ofString(body));
        for (int i = 0; i + 1 < headersKV.length; i += 2) {
            req.header(headersKV[i], headersKV[i + 1]);
        }
        try {
            return CLIENT.send(req.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
    }

    protected ValidationResult fromStatus(int status) {
        if (status == 200) return ValidationResult.VALID;
        if (status == 401 || status == 403) return ValidationResult.INVALID;
        if (status == 429) return ValidationResult.RATE_LIMITED;
        if (status >= 500) return ValidationResult.NETWORK_ERROR;
        return ValidationResult.UNKNOWN;
    }
}
