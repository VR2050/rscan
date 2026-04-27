package com.facebook.react.uimanager;

import d1.C0506b;
import h2.AbstractC0558d;
import h2.EnumC0561g;
import kotlin.Lazy;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class b1 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final b1 f7591a = new b1();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Lazy f7592b = AbstractC0558d.a(EnumC0561g.f9269b, new InterfaceC0688a() { // from class: com.facebook.react.uimanager.a1
        @Override // s2.InterfaceC0688a
        public final Object a() {
            return b1.d();
        }
    });

    private b1() {
    }

    public static final C0506b b() {
        return f7591a.c();
    }

    private final C0506b c() {
        return (C0506b) f7592b.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final C0506b d() {
        return new C0506b(1024);
    }
}
