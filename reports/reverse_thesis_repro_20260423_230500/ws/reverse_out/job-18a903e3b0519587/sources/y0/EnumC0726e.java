package y0;

import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: renamed from: y0.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class EnumC0726e {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f10391c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final EnumC0726e[] f10392d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final EnumC0726e f10393e = new EnumC0726e("UNKNOWN", 0, -1);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final EnumC0726e f10394f = new EnumC0726e("REQUESTED", 1, 0);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final EnumC0726e f10395g = new EnumC0726e("INTERMEDIATE_AVAILABLE", 2, 2);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final EnumC0726e f10396h = new EnumC0726e("SUCCESS", 3, 3);

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final EnumC0726e f10397i = new EnumC0726e("ERROR", 4, 5);

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final EnumC0726e f10398j = new EnumC0726e("EMPTY_EVENT", 5, 7);

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public static final EnumC0726e f10399k = new EnumC0726e("RELEASED", 6, 8);

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static final /* synthetic */ EnumC0726e[] f10400l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f10401m;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f10402b;

    /* JADX INFO: renamed from: y0.e$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX INFO: renamed from: y0.e$b */
    public /* synthetic */ class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f10403a;

        static {
            int[] iArr = new int[EnumC0726e.values().length];
            try {
                iArr[EnumC0726e.f10394f.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[EnumC0726e.f10396h.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[EnumC0726e.f10395g.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[EnumC0726e.f10397i.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                iArr[EnumC0726e.f10399k.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            f10403a = iArr;
        }
    }

    static {
        EnumC0726e[] enumC0726eArrA = a();
        f10400l = enumC0726eArrA;
        f10401m = AbstractC0628a.a(enumC0726eArrA);
        f10391c = new a(null);
        f10392d = values();
    }

    private EnumC0726e(String str, int i3, int i4) {
        this.f10402b = i4;
    }

    private static final /* synthetic */ EnumC0726e[] a() {
        return new EnumC0726e[]{f10393e, f10394f, f10395g, f10396h, f10397i, f10398j, f10399k};
    }

    public static EnumC0726e valueOf(String str) {
        return (EnumC0726e) Enum.valueOf(EnumC0726e.class, str);
    }

    public static EnumC0726e[] values() {
        return (EnumC0726e[]) f10400l.clone();
    }

    @Override // java.lang.Enum
    public String toString() {
        int i3 = b.f10403a[ordinal()];
        return i3 != 1 ? i3 != 2 ? i3 != 3 ? i3 != 4 ? i3 != 5 ? "unknown" : "released" : "error" : "intermediate_available" : "success" : "requested";
    }
}
