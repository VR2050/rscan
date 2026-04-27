package com.facebook.react.uimanager;

import java.util.Locale;
import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: renamed from: com.facebook.react.uimanager.g0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class EnumC0446g0 {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f7605b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final EnumC0446g0 f7606c = new EnumC0446g0("NONE", 0);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final EnumC0446g0 f7607d = new EnumC0446g0("BOX_NONE", 1);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final EnumC0446g0 f7608e = new EnumC0446g0("BOX_ONLY", 2);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final EnumC0446g0 f7609f = new EnumC0446g0("AUTO", 3);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ EnumC0446g0[] f7610g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f7611h;

    /* JADX INFO: renamed from: com.facebook.react.uimanager.g0$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final boolean a(EnumC0446g0 enumC0446g0) {
            t2.j.f(enumC0446g0, "pointerEvents");
            return enumC0446g0 == EnumC0446g0.f7609f || enumC0446g0 == EnumC0446g0.f7608e;
        }

        public final boolean b(EnumC0446g0 enumC0446g0) {
            t2.j.f(enumC0446g0, "pointerEvents");
            return enumC0446g0 == EnumC0446g0.f7609f || enumC0446g0 == EnumC0446g0.f7607d;
        }

        public final EnumC0446g0 c(String str) {
            if (str == null) {
                return EnumC0446g0.f7609f;
            }
            Locale locale = Locale.US;
            t2.j.e(locale, "US");
            String upperCase = str.toUpperCase(locale);
            t2.j.e(upperCase, "toUpperCase(...)");
            return EnumC0446g0.valueOf(z2.g.q(upperCase, "-", "_", false, 4, null));
        }

        private a() {
        }
    }

    static {
        EnumC0446g0[] enumC0446g0ArrA = a();
        f7610g = enumC0446g0ArrA;
        f7611h = AbstractC0628a.a(enumC0446g0ArrA);
        f7605b = new a(null);
    }

    private EnumC0446g0(String str, int i3) {
    }

    private static final /* synthetic */ EnumC0446g0[] a() {
        return new EnumC0446g0[]{f7606c, f7607d, f7608e, f7609f};
    }

    public static final boolean b(EnumC0446g0 enumC0446g0) {
        return f7605b.a(enumC0446g0);
    }

    public static final boolean c(EnumC0446g0 enumC0446g0) {
        return f7605b.b(enumC0446g0);
    }

    public static final EnumC0446g0 d(String str) {
        return f7605b.c(str);
    }

    public static EnumC0446g0 valueOf(String str) {
        return (EnumC0446g0) Enum.valueOf(EnumC0446g0.class, str);
    }

    public static EnumC0446g0[] values() {
        return (EnumC0446g0[]) f7610g.clone();
    }
}
