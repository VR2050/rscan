package c1;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: renamed from: c1.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class EnumC0334f {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final EnumC0334f f5563b = new EnumC0334f("JSC", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final EnumC0334f f5564c = new EnumC0334f("HERMES", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final /* synthetic */ EnumC0334f[] f5565d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f5566e;

    static {
        EnumC0334f[] enumC0334fArrA = a();
        f5565d = enumC0334fArrA;
        f5566e = AbstractC0628a.a(enumC0334fArrA);
    }

    private EnumC0334f(String str, int i3) {
    }

    private static final /* synthetic */ EnumC0334f[] a() {
        return new EnumC0334f[]{f5563b, f5564c};
    }

    public static EnumC0334f valueOf(String str) {
        return (EnumC0334f) Enum.valueOf(EnumC0334f.class, str);
    }

    public static EnumC0334f[] values() {
        return (EnumC0334f[]) f5565d.clone();
    }
}
