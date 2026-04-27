package d1;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class f {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final f f9159b = new f("EXPERIMENTAL", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final f f9160c = new f("CANARY", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final f f9161d = new f("STABLE", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final /* synthetic */ f[] f9162e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f9163f;

    static {
        f[] fVarArrA = a();
        f9162e = fVarArrA;
        f9163f = AbstractC0628a.a(fVarArrA);
    }

    private f(String str, int i3) {
    }

    private static final /* synthetic */ f[] a() {
        return new f[]{f9159b, f9160c, f9161d};
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) f9162e.clone();
    }
}
