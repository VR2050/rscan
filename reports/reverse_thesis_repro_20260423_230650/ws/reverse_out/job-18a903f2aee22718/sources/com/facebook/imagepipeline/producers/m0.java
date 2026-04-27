package com.facebook.imagepipeline.producers;

import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public abstract class m0 extends V.e {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final InterfaceC0369n f6312c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final g0 f6313d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final e0 f6314e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final String f6315f;

    public m0(InterfaceC0369n interfaceC0369n, g0 g0Var, e0 e0Var, String str) {
        t2.j.f(interfaceC0369n, "consumer");
        t2.j.f(g0Var, "producerListener");
        t2.j.f(e0Var, "producerContext");
        t2.j.f(str, "producerName");
        this.f6312c = interfaceC0369n;
        this.f6313d = g0Var;
        this.f6314e = e0Var;
        this.f6315f = str;
        g0Var.g(e0Var, str);
    }

    @Override // V.e
    protected void d() {
        g0 g0Var = this.f6313d;
        e0 e0Var = this.f6314e;
        String str = this.f6315f;
        g0Var.f(e0Var, str, g0Var.j(e0Var, str) ? g() : null);
        this.f6312c.b();
    }

    @Override // V.e
    protected void e(Exception exc) {
        t2.j.f(exc, "e");
        g0 g0Var = this.f6313d;
        e0 e0Var = this.f6314e;
        String str = this.f6315f;
        g0Var.i(e0Var, str, exc, g0Var.j(e0Var, str) ? h(exc) : null);
        this.f6312c.a(exc);
    }

    @Override // V.e
    protected void f(Object obj) {
        g0 g0Var = this.f6313d;
        e0 e0Var = this.f6314e;
        String str = this.f6315f;
        g0Var.d(e0Var, str, g0Var.j(e0Var, str) ? i(obj) : null);
        this.f6312c.d(obj, 1);
    }

    protected Map g() {
        return null;
    }

    protected Map h(Exception exc) {
        return null;
    }

    protected Map i(Object obj) {
        return null;
    }
}
