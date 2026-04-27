package y0;

import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class n {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f10488c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final n[] f10489d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final n f10490e = new n("UNKNOWN", 0, -1);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final n f10491f = new n("VISIBLE", 1, 1);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final n f10492g = new n("INVISIBLE", 2, 2);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final /* synthetic */ n[] f10493h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f10494i;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f10495b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    static {
        n[] nVarArrA = a();
        f10493h = nVarArrA;
        f10494i = AbstractC0628a.a(nVarArrA);
        f10488c = new a(null);
        f10489d = values();
    }

    private n(String str, int i3, int i4) {
        this.f10495b = i4;
    }

    private static final /* synthetic */ n[] a() {
        return new n[]{f10490e, f10491f, f10492g};
    }

    public static n valueOf(String str) {
        return (n) Enum.valueOf(n.class, str);
    }

    public static n[] values() {
        return (n[]) f10493h.clone();
    }
}
