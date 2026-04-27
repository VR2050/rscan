package com.facebook.react.uimanager;

import h2.AbstractC0558d;
import h2.EnumC0561g;
import kotlin.Lazy;
import s2.InterfaceC0688a;

/* JADX INFO: renamed from: com.facebook.react.uimanager.u0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0473u0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0473u0 f7758a = new C0473u0();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Lazy f7759b = AbstractC0558d.a(EnumC0561g.f9271d, new InterfaceC0688a() { // from class: com.facebook.react.uimanager.t0
        @Override // s2.InterfaceC0688a
        public final Object a() {
            return C0473u0.c();
        }
    });

    private C0473u0() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final com.facebook.yoga.c c() {
        com.facebook.yoga.c cVarA = com.facebook.yoga.d.a();
        cVarA.b(0.0f);
        cVarA.a(com.facebook.yoga.k.ALL);
        return cVarA;
    }

    public final com.facebook.yoga.c b() {
        Object value = f7759b.getValue();
        t2.j.e(value, "getValue(...)");
        return (com.facebook.yoga.c) value;
    }
}
