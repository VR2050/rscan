package com.facebook.react.uimanager;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: renamed from: com.facebook.react.uimanager.a0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class EnumC0434a0 {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final EnumC0434a0 f7568b = new EnumC0434a0("PARENT", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final EnumC0434a0 f7569c = new EnumC0434a0("LEAF", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final EnumC0434a0 f7570d = new EnumC0434a0("NONE", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final /* synthetic */ EnumC0434a0[] f7571e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f7572f;

    static {
        EnumC0434a0[] enumC0434a0ArrA = a();
        f7571e = enumC0434a0ArrA;
        f7572f = AbstractC0628a.a(enumC0434a0ArrA);
    }

    private EnumC0434a0(String str, int i3) {
    }

    private static final /* synthetic */ EnumC0434a0[] a() {
        return new EnumC0434a0[]{f7568b, f7569c, f7570d};
    }

    public static EnumC0434a0 valueOf(String str) {
        return (EnumC0434a0) Enum.valueOf(EnumC0434a0.class, str);
    }

    public static EnumC0434a0[] values() {
        return (EnumC0434a0[]) f7571e.clone();
    }
}
