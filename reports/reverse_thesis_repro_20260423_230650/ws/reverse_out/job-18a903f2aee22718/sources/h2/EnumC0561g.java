package h2;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: renamed from: h2.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class EnumC0561g {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final EnumC0561g f9269b = new EnumC0561g("SYNCHRONIZED", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final EnumC0561g f9270c = new EnumC0561g("PUBLICATION", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final EnumC0561g f9271d = new EnumC0561g("NONE", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final /* synthetic */ EnumC0561g[] f9272e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f9273f;

    static {
        EnumC0561g[] enumC0561gArrA = a();
        f9272e = enumC0561gArrA;
        f9273f = AbstractC0628a.a(enumC0561gArrA);
    }

    private EnumC0561g(String str, int i3) {
    }

    private static final /* synthetic */ EnumC0561g[] a() {
        return new EnumC0561g[]{f9269b, f9270c, f9271d};
    }

    public static EnumC0561g valueOf(String str) {
        return (EnumC0561g) Enum.valueOf(EnumC0561g.class, str);
    }

    public static EnumC0561g[] values() {
        return (EnumC0561g[]) f9272e.clone();
    }
}
