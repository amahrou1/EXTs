package io.github.abdallah.secretscanner.validator;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenBucketTest {

    @Test
    void fiveTasksThrottledToThreeSecondIntervals() throws InterruptedException {
        ValidationThrottle throttle = new ValidationThrottle(3_000);
        long start = System.currentTimeMillis();
        for (int i = 0; i < 5; i++) {
            throttle.executeThrottled(() -> {
                try { Thread.sleep(50); } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed >= 12_000,
                "5 throttled tasks at 3s intervals should take >= 12s, took " + elapsed + "ms");
    }

    @Test
    void firstTaskRunsImmediately() throws InterruptedException {
        ValidationThrottle throttle = new ValidationThrottle(3_000);
        long start = System.currentTimeMillis();
        throttle.executeThrottled(() -> {});
        long elapsed = System.currentTimeMillis() - start;
        assertTrue(elapsed < 500, "First task should run immediately, took " + elapsed + "ms");
    }
}
