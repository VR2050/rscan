package Q1;

import java.util.Locale;
import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class p {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2498b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final p f2499c = new p("VISIBLE", 0);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final p f2500d = new p("HIDDEN", 1);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final p f2501e = new p("SCROLL", 2);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ p[] f2502f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f2503g;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final p a(String str) {
            t2.j.f(str, "overflow");
            String lowerCase = str.toLowerCase(Locale.ROOT);
            t2.j.e(lowerCase, "toLowerCase(...)");
            int iHashCode = lowerCase.hashCode();
            if (iHashCode != -1217487446) {
                if (iHashCode != -907680051) {
                    if (iHashCode == 466743410 && lowerCase.equals("visible")) {
                        return p.f2499c;
                    }
                } else if (lowerCase.equals("scroll")) {
                    return p.f2501e;
                }
            } else if (lowerCase.equals("hidden")) {
                return p.f2500d;
            }
            return null;
        }

        private a() {
        }
    }

    static {
        p[] pVarArrA = a();
        f2502f = pVarArrA;
        f2503g = AbstractC0628a.a(pVarArrA);
        f2498b = new a(null);
    }

    private p(String str, int i3) {
    }

    private static final /* synthetic */ p[] a() {
        return new p[]{f2499c, f2500d, f2501e};
    }

    public static final p b(String str) {
        return f2498b.a(str);
    }

    public static p valueOf(String str) {
        return (p) Enum.valueOf(p.class, str);
    }

    public static p[] values() {
        return (p[]) f2502f.clone();
    }
}
