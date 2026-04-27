package com.facebook.imagepipeline.producers;

import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public final class B implements p0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f6093a;

    public B(Executor executor) {
        if (executor == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.f6093a = executor;
    }

    @Override // com.facebook.imagepipeline.producers.p0
    public void a(Runnable runnable) {
        t2.j.f(runnable, "runnable");
        this.f6093a.execute(runnable);
    }

    @Override // com.facebook.imagepipeline.producers.p0
    public void b(Runnable runnable) {
        t2.j.f(runnable, "runnable");
    }
}
