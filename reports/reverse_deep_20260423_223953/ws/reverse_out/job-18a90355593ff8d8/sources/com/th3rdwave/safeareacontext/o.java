package com.th3rdwave.safeareacontext;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class o {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final o f8769b = new o("PADDING", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final o f8770c = new o("MARGIN", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final /* synthetic */ o[] f8771d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f8772e;

    static {
        o[] oVarArrA = a();
        f8771d = oVarArrA;
        f8772e = AbstractC0628a.a(oVarArrA);
    }

    private o(String str, int i3) {
    }

    private static final /* synthetic */ o[] a() {
        return new o[]{f8769b, f8770c};
    }

    public static o valueOf(String str) {
        return (o) Enum.valueOf(o.class, str);
    }

    public static o[] values() {
        return (o[]) f8771d.clone();
    }
}
