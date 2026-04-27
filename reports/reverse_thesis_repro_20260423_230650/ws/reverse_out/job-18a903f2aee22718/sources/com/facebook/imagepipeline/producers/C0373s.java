package com.facebook.imagepipeline.producers;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.s, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0373s implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d0 f6371a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ScheduledExecutorService f6372b;

    public C0373s(d0 d0Var, ScheduledExecutorService scheduledExecutorService) {
        t2.j.f(d0Var, "inputProducer");
        this.f6371a = d0Var;
        this.f6372b = scheduledExecutorService;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void d(C0373s c0373s, InterfaceC0369n interfaceC0369n, e0 e0Var) {
        t2.j.f(c0373s, "this$0");
        t2.j.f(interfaceC0369n, "$consumer");
        t2.j.f(e0Var, "$context");
        c0373s.f6371a.a(interfaceC0369n, e0Var);
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(final InterfaceC0369n interfaceC0369n, final e0 e0Var) {
        t2.j.f(interfaceC0369n, "consumer");
        t2.j.f(e0Var, "context");
        T0.b bVarW = e0Var.W();
        ScheduledExecutorService scheduledExecutorService = this.f6372b;
        if (scheduledExecutorService != null) {
            scheduledExecutorService.schedule(new Runnable() { // from class: com.facebook.imagepipeline.producers.r
                @Override // java.lang.Runnable
                public final void run() {
                    C0373s.d(this.f6360b, interfaceC0369n, e0Var);
                }
            }, bVarW.e(), TimeUnit.MILLISECONDS);
        } else {
            this.f6371a.a(interfaceC0369n, e0Var);
        }
    }
}
