package com.facebook.imagepipeline.producers;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public final class q0 implements p0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f6357a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f6358b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Deque f6359c;

    public q0(Executor executor) {
        t2.j.f(executor, "executor");
        this.f6357a = executor;
        this.f6359c = new ArrayDeque();
    }

    @Override // com.facebook.imagepipeline.producers.p0
    public synchronized void a(Runnable runnable) {
        try {
            t2.j.f(runnable, "runnable");
            if (this.f6358b) {
                this.f6359c.add(runnable);
            } else {
                this.f6357a.execute(runnable);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.facebook.imagepipeline.producers.p0
    public synchronized void b(Runnable runnable) {
        t2.j.f(runnable, "runnable");
        this.f6359c.remove(runnable);
    }
}
