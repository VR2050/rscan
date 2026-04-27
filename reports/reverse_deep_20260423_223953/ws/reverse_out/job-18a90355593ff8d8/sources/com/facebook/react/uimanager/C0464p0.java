package com.facebook.react.uimanager;

/* JADX INFO: renamed from: com.facebook.react.uimanager.p0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0464p0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0464p0 f7731a = new C0464p0();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static int f7732b = 1;

    private C0464p0() {
    }

    public static final synchronized int a() {
        int i3;
        i3 = f7732b;
        f7732b = i3 + 10;
        return i3;
    }
}
