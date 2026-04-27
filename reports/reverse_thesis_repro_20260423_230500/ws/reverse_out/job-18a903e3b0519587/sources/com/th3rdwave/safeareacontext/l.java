package com.th3rdwave.safeareacontext;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class l {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final l f8757b = new l("OFF", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final l f8758c = new l("ADDITIVE", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final l f8759d = new l("MAXIMUM", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final /* synthetic */ l[] f8760e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f8761f;

    static {
        l[] lVarArrA = a();
        f8760e = lVarArrA;
        f8761f = AbstractC0628a.a(lVarArrA);
    }

    private l(String str, int i3) {
    }

    private static final /* synthetic */ l[] a() {
        return new l[]{f8757b, f8758c, f8759d};
    }

    public static l valueOf(String str) {
        return (l) Enum.valueOf(l.class, str);
    }

    public static l[] values() {
        return (l[]) f8760e.clone();
    }
}
