package com.facebook.react.uimanager;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class X {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final X f7535b = new X("POINT", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final X f7536c = new X("PERCENT", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final /* synthetic */ X[] f7537d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f7538e;

    static {
        X[] xArrA = a();
        f7537d = xArrA;
        f7538e = AbstractC0628a.a(xArrA);
    }

    private X(String str, int i3) {
    }

    private static final /* synthetic */ X[] a() {
        return new X[]{f7535b, f7536c};
    }

    public static X valueOf(String str) {
        return (X) Enum.valueOf(X.class, str);
    }

    public static X[] values() {
        return (X[]) f7537d.clone();
    }
}
