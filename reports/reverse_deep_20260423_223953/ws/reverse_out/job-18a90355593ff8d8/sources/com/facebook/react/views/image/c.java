package com.facebook.react.views.image;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final c f7798b = new c("AUTO", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final c f7799c = new c("RESIZE", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final c f7800d = new c("SCALE", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final c f7801e = new c("NONE", 3);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ c[] f7802f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f7803g;

    static {
        c[] cVarArrA = a();
        f7802f = cVarArrA;
        f7803g = AbstractC0628a.a(cVarArrA);
    }

    private c(String str, int i3) {
    }

    private static final /* synthetic */ c[] a() {
        return new c[]{f7798b, f7799c, f7800d, f7801e};
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) f7802f.clone();
    }
}
