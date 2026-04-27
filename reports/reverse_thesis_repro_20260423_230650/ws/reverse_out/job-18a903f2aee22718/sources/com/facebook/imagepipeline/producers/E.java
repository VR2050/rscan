package com.facebook.imagepipeline.producers;

import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public abstract class E implements g0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final h0 f6113a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final g0 f6114b;

    public E(h0 h0Var, g0 g0Var) {
        this.f6113a = h0Var;
        this.f6114b = g0Var;
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void b(e0 e0Var, String str, String str2) {
        t2.j.f(e0Var, "context");
        h0 h0Var = this.f6113a;
        if (h0Var != null) {
            h0Var.e(e0Var.getId(), str, str2);
        }
        g0 g0Var = this.f6114b;
        if (g0Var != null) {
            g0Var.b(e0Var, str, str2);
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void d(e0 e0Var, String str, Map map) {
        t2.j.f(e0Var, "context");
        h0 h0Var = this.f6113a;
        if (h0Var != null) {
            h0Var.f(e0Var.getId(), str, map);
        }
        g0 g0Var = this.f6114b;
        if (g0Var != null) {
            g0Var.d(e0Var, str, map);
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void e(e0 e0Var, String str, boolean z3) {
        t2.j.f(e0Var, "context");
        h0 h0Var = this.f6113a;
        if (h0Var != null) {
            h0Var.k(e0Var.getId(), str, z3);
        }
        g0 g0Var = this.f6114b;
        if (g0Var != null) {
            g0Var.e(e0Var, str, z3);
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void f(e0 e0Var, String str, Map map) {
        t2.j.f(e0Var, "context");
        h0 h0Var = this.f6113a;
        if (h0Var != null) {
            h0Var.i(e0Var.getId(), str, map);
        }
        g0 g0Var = this.f6114b;
        if (g0Var != null) {
            g0Var.f(e0Var, str, map);
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void g(e0 e0Var, String str) {
        t2.j.f(e0Var, "context");
        h0 h0Var = this.f6113a;
        if (h0Var != null) {
            h0Var.g(e0Var.getId(), str);
        }
        g0 g0Var = this.f6114b;
        if (g0Var != null) {
            g0Var.g(e0Var, str);
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public void i(e0 e0Var, String str, Throwable th, Map map) {
        t2.j.f(e0Var, "context");
        h0 h0Var = this.f6113a;
        if (h0Var != null) {
            h0Var.h(e0Var.getId(), str, th, map);
        }
        g0 g0Var = this.f6114b;
        if (g0Var != null) {
            g0Var.i(e0Var, str, th, map);
        }
    }

    @Override // com.facebook.imagepipeline.producers.g0
    public boolean j(e0 e0Var, String str) {
        t2.j.f(e0Var, "context");
        h0 h0Var = this.f6113a;
        Boolean boolValueOf = h0Var != null ? Boolean.valueOf(h0Var.c(e0Var.getId())) : null;
        if (!t2.j.b(boolValueOf, Boolean.TRUE)) {
            g0 g0Var = this.f6114b;
            boolValueOf = g0Var != null ? Boolean.valueOf(g0Var.j(e0Var, str)) : null;
        }
        if (boolValueOf != null) {
            return boolValueOf.booleanValue();
        }
        return false;
    }
}
