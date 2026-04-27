package com.facebook.imagepipeline.producers;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.t, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0374t extends AbstractC0358c {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0369n f6373b;

    public AbstractC0374t(InterfaceC0369n interfaceC0369n) {
        t2.j.f(interfaceC0369n, "consumer");
        this.f6373b = interfaceC0369n;
    }

    @Override // com.facebook.imagepipeline.producers.AbstractC0358c
    protected void g() {
        this.f6373b.b();
    }

    @Override // com.facebook.imagepipeline.producers.AbstractC0358c
    protected void h(Throwable th) {
        t2.j.f(th, "t");
        this.f6373b.a(th);
    }

    @Override // com.facebook.imagepipeline.producers.AbstractC0358c
    protected void j(float f3) {
        this.f6373b.c(f3);
    }

    public final InterfaceC0369n p() {
        return this.f6373b;
    }
}
