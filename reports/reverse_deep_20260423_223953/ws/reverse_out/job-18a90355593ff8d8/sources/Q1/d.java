package Q1;

import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class d {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final d f2402b = new d("BORDER_RADIUS", 0);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final d f2403c = new d("BORDER_TOP_LEFT_RADIUS", 1);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final d f2404d = new d("BORDER_TOP_RIGHT_RADIUS", 2);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final d f2405e = new d("BORDER_BOTTOM_RIGHT_RADIUS", 3);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final d f2406f = new d("BORDER_BOTTOM_LEFT_RADIUS", 4);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final d f2407g = new d("BORDER_TOP_START_RADIUS", 5);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final d f2408h = new d("BORDER_TOP_END_RADIUS", 6);

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final d f2409i = new d("BORDER_BOTTOM_START_RADIUS", 7);

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final d f2410j = new d("BORDER_BOTTOM_END_RADIUS", 8);

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public static final d f2411k = new d("BORDER_END_END_RADIUS", 9);

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static final d f2412l = new d("BORDER_END_START_RADIUS", 10);

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    public static final d f2413m = new d("BORDER_START_END_RADIUS", 11);

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    public static final d f2414n = new d("BORDER_START_START_RADIUS", 12);

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final /* synthetic */ d[] f2415o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f2416p;

    static {
        d[] dVarArrA = a();
        f2415o = dVarArrA;
        f2416p = AbstractC0628a.a(dVarArrA);
    }

    private d(String str, int i3) {
    }

    private static final /* synthetic */ d[] a() {
        return new d[]{f2402b, f2403c, f2404d, f2405e, f2406f, f2407g, f2408h, f2409i, f2410j, f2411k, f2412l, f2413m, f2414n};
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) f2415o.clone();
    }
}
