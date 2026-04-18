package io.github.abdallah.secretscanner.validator;

import java.util.concurrent.atomic.AtomicLong;

public final class ValidationThrottle {

    private final long cooldownMs;
    private final AtomicLong lastRunMs = new AtomicLong(0);

    public ValidationThrottle(long cooldownMs) {
        this.cooldownMs = cooldownMs;
    }

    public void executeThrottled(Runnable task) throws InterruptedException {
        synchronized (this) {
            long now = System.currentTimeMillis();
            long wait = cooldownMs - (now - lastRunMs.get());
            if (wait > 0) Thread.sleep(wait);
            lastRunMs.set(System.currentTimeMillis());
        }
        task.run();
    }

    public long cooldownMs() { return cooldownMs; }
}
