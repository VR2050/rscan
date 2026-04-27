package com.facebook.imagepipeline.producers;

import android.net.Uri;

/* JADX INFO: loaded from: classes.dex */
public abstract class C {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final InterfaceC0369n f6094a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final e0 f6095b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long f6096c = 0;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f6097d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private H0.b f6098e;

    public C(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        this.f6094a = interfaceC0369n;
        this.f6095b = e0Var;
    }

    public InterfaceC0369n a() {
        return this.f6094a;
    }

    public e0 b() {
        return this.f6095b;
    }

    public long c() {
        return this.f6096c;
    }

    public g0 d() {
        return this.f6095b.P();
    }

    public int e() {
        return this.f6097d;
    }

    public H0.b f() {
        return this.f6098e;
    }

    public Uri g() {
        return this.f6095b.W().v();
    }

    public void h(long j3) {
        this.f6096c = j3;
    }

    public void i(int i3) {
        this.f6097d = i3;
    }

    public void j(H0.b bVar) {
        this.f6098e = bVar;
    }
}
