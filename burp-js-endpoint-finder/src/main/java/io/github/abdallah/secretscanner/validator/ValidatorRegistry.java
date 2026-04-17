package io.github.abdallah.secretscanner.validator;

import io.github.abdallah.secretscanner.validator.impl.*;

import java.util.HashMap;
import java.util.Map;

public final class ValidatorRegistry {

    private final Map<String, Validator> map = new HashMap<>();

    public ValidatorRegistry() {
        register("anthropic",           new AnthropicValidator());
        register("openai",              new OpenAIValidator());
        register("gemini",              new GeminiValidator());
        register("huggingface",         new HFValidator());
        register("grok",                new GrokValidator());
        register("groq",                new GroqValidator());
        register("replicate",           new ReplicateValidator());
        register("github",              new GitHubValidator());
        register("slack",               new SlackValidator());
        register("stripe",              new StripeValidator());
        register("aws-caller-identity", new AWSValidator());
    }

    public void register(String id, Validator validator) {
        map.put(id, validator);
    }

    /** Returns null if no validator is registered for this id. */
    public Validator get(String validatorId) {
        return validatorId == null ? null : map.get(validatorId);
    }
}
