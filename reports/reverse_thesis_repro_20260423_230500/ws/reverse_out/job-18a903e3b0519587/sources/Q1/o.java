package Q1;

import java.util.Locale;
import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class o {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2492b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final o f2493c = new o("SOLID", 0);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final o f2494d = new o("DASHED", 1);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final o f2495e = new o("DOTTED", 2);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ o[] f2496f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f2497g;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final o a(String str) {
            t2.j.f(str, "outlineStyle");
            String lowerCase = str.toLowerCase(Locale.ROOT);
            t2.j.e(lowerCase, "toLowerCase(...)");
            int iHashCode = lowerCase.hashCode();
            if (iHashCode != -1338941519) {
                if (iHashCode != -1325970902) {
                    if (iHashCode == 109618859 && lowerCase.equals("solid")) {
                        return o.f2493c;
                    }
                } else if (lowerCase.equals("dotted")) {
                    return o.f2495e;
                }
            } else if (lowerCase.equals("dashed")) {
                return o.f2494d;
            }
            return null;
        }

        private a() {
        }
    }

    static {
        o[] oVarArrA = a();
        f2496f = oVarArrA;
        f2497g = AbstractC0628a.a(oVarArrA);
        f2492b = new a(null);
    }

    private o(String str, int i3) {
    }

    private static final /* synthetic */ o[] a() {
        return new o[]{f2493c, f2494d, f2495e};
    }

    public static final o b(String str) {
        return f2492b.a(str);
    }

    public static o valueOf(String str) {
        return (o) Enum.valueOf(o.class, str);
    }

    public static o[] values() {
        return (o[]) f2496f.clone();
    }
}
