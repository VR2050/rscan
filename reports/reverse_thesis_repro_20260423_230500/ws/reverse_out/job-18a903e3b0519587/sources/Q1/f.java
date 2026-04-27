package Q1;

import java.util.Locale;
import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class f {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2431b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final f f2432c = new f("SOLID", 0);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final f f2433d = new f("DASHED", 1);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final f f2434e = new f("DOTTED", 2);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ f[] f2435f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f2436g;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final f a(String str) {
            t2.j.f(str, "borderStyle");
            String lowerCase = str.toLowerCase(Locale.ROOT);
            t2.j.e(lowerCase, "toLowerCase(...)");
            int iHashCode = lowerCase.hashCode();
            if (iHashCode != -1338941519) {
                if (iHashCode != -1325970902) {
                    if (iHashCode == 109618859 && lowerCase.equals("solid")) {
                        return f.f2432c;
                    }
                } else if (lowerCase.equals("dotted")) {
                    return f.f2434e;
                }
            } else if (lowerCase.equals("dashed")) {
                return f.f2433d;
            }
            return null;
        }

        private a() {
        }
    }

    static {
        f[] fVarArrA = a();
        f2435f = fVarArrA;
        f2436g = AbstractC0628a.a(fVarArrA);
        f2431b = new a(null);
    }

    private f(String str, int i3) {
    }

    private static final /* synthetic */ f[] a() {
        return new f[]{f2432c, f2433d, f2434e};
    }

    public static final f b(String str) {
        return f2431b.a(str);
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) f2435f.clone();
    }
}
