package y0;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: renamed from: y0.k, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class EnumC0732k {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final EnumC0732k f10481b = new EnumC0732k("VITO_V2", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final EnumC0732k f10482c = new EnumC0732k("VITO_V1", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final EnumC0732k f10483d = new EnumC0732k("DRAWEE", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final EnumC0732k f10484e = new EnumC0732k("OTHER", 3);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ EnumC0732k[] f10485f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f10486g;

    static {
        EnumC0732k[] enumC0732kArrA = a();
        f10485f = enumC0732kArrA;
        f10486g = AbstractC0628a.a(enumC0732kArrA);
    }

    private EnumC0732k(String str, int i3) {
    }

    private static final /* synthetic */ EnumC0732k[] a() {
        return new EnumC0732k[]{f10481b, f10482c, f10483d, f10484e};
    }

    public static EnumC0732k valueOf(String str) {
        return (EnumC0732k) Enum.valueOf(EnumC0732k.class, str);
    }

    public static EnumC0732k[] values() {
        return (EnumC0732k[]) f10485f.clone();
    }
}
