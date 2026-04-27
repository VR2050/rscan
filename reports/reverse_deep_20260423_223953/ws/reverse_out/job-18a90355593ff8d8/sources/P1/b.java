package P1;

import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2160b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final b f2161c = new b("OPACITY", 0);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final b f2162d = new b("SCALE_X", 1);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final b f2163e = new b("SCALE_Y", 2);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final b f2164f = new b("SCALE_XY", 3);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ b[] f2165g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f2166h;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
        public final b a(String str) {
            t2.j.f(str, "name");
            switch (str.hashCode()) {
                case -1267206133:
                    if (str.equals("opacity")) {
                        return b.f2161c;
                    }
                    break;
                case -908189618:
                    if (str.equals("scaleX")) {
                        return b.f2162d;
                    }
                    break;
                case -908189617:
                    if (str.equals("scaleY")) {
                        return b.f2163e;
                    }
                    break;
                case 1910893003:
                    if (str.equals("scaleXY")) {
                        return b.f2164f;
                    }
                    break;
            }
            throw new IllegalArgumentException("Unsupported animated property: " + str);
        }

        private a() {
        }
    }

    static {
        b[] bVarArrA = a();
        f2165g = bVarArrA;
        f2166h = AbstractC0628a.a(bVarArrA);
        f2160b = new a(null);
    }

    private b(String str, int i3) {
    }

    private static final /* synthetic */ b[] a() {
        return new b[]{f2161c, f2162d, f2163e, f2164f};
    }

    public static final b b(String str) {
        return f2160b.a(str);
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) f2165g.clone();
    }
}
