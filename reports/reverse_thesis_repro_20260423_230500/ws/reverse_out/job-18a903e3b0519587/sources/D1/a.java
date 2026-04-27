package D1;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f593b = new a("DEFAULT", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f594c = new a("RELOAD", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f595d = new a("FORCE_CACHE", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f596e = new a("ONLY_IF_CACHED", 3);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ a[] f597f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f598g;

    static {
        a[] aVarArrA = a();
        f597f = aVarArrA;
        f598g = AbstractC0628a.a(aVarArrA);
    }

    private a(String str, int i3) {
    }

    private static final /* synthetic */ a[] a() {
        return new a[]{f593b, f594c, f595d, f596e};
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) f597f.clone();
    }
}
