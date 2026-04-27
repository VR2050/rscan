package io.openinstall.sdk;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: loaded from: classes3.dex */
class dc implements ThreadFactory {
    private final AtomicInteger a = new AtomicInteger(1);

    dc() {
    }

    @Override // java.util.concurrent.ThreadFactory
    public Thread newThread(Runnable runnable) {
        Thread thread = new Thread(runnable, "pool-ot-" + this.a.getAndIncrement());
        thread.setUncaughtExceptionHandler(new dd(this));
        return thread;
    }
}
