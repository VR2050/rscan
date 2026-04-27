package com.facebook.react.views.view;

/* JADX INFO: loaded from: classes.dex */
public final class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final d f8288a = new d();

    private d() {
    }

    private final int a(double d3) {
        return Math.max(0, Math.min(255, u2.a.b(d3)));
    }

    public static final int b(double d3, double d4, double d5, double d6) {
        d dVar = f8288a;
        return (dVar.a(d3) << 16) | (dVar.a(d6 * ((double) 255)) << 24) | (dVar.a(d4) << 8) | dVar.a(d5);
    }
}
