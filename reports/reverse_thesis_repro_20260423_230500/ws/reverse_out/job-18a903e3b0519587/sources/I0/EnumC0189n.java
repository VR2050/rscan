package I0;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: renamed from: I0.n, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class EnumC0189n {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final EnumC0189n f1224b = new EnumC0189n("ALWAYS", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final EnumC0189n f1225c = new EnumC0189n("AUTO", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final EnumC0189n f1226d = new EnumC0189n("NEVER", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final /* synthetic */ EnumC0189n[] f1227e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f1228f;

    static {
        EnumC0189n[] enumC0189nArrA = a();
        f1227e = enumC0189nArrA;
        f1228f = AbstractC0628a.a(enumC0189nArrA);
    }

    private EnumC0189n(String str, int i3) {
    }

    private static final /* synthetic */ EnumC0189n[] a() {
        return new EnumC0189n[]{f1224b, f1225c, f1226d};
    }

    public static EnumC0189n valueOf(String str) {
        return (EnumC0189n) Enum.valueOf(EnumC0189n.class, str);
    }

    public static EnumC0189n[] values() {
        return (EnumC0189n[]) f1227e.clone();
    }
}
