package P1;

import h2.C0562h;
import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class g {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2189b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final g f2190c = new g("CREATE", 0);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final g f2191d = new g("UPDATE", 1);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final g f2192e = new g("DELETE", 2);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ g[] f2193f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f2194g;

    public static final class a {

        /* JADX INFO: renamed from: P1.g$a$a, reason: collision with other inner class name */
        public /* synthetic */ class C0034a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            public static final /* synthetic */ int[] f2195a;

            static {
                int[] iArr = new int[g.values().length];
                try {
                    iArr[g.f2190c.ordinal()] = 1;
                } catch (NoSuchFieldError unused) {
                }
                try {
                    iArr[g.f2191d.ordinal()] = 2;
                } catch (NoSuchFieldError unused2) {
                }
                try {
                    iArr[g.f2192e.ordinal()] = 3;
                } catch (NoSuchFieldError unused3) {
                }
                f2195a = iArr;
            }
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final String a(g gVar) {
            t2.j.f(gVar, "type");
            int i3 = C0034a.f2195a[gVar.ordinal()];
            if (i3 == 1) {
                return "create";
            }
            if (i3 == 2) {
                return "update";
            }
            if (i3 == 3) {
                return "delete";
            }
            throw new C0562h();
        }

        private a() {
        }
    }

    static {
        g[] gVarArrA = a();
        f2193f = gVarArrA;
        f2194g = AbstractC0628a.a(gVarArrA);
        f2189b = new a(null);
    }

    private g(String str, int i3) {
    }

    private static final /* synthetic */ g[] a() {
        return new g[]{f2190c, f2191d, f2192e};
    }

    public static final String b(g gVar) {
        return f2189b.a(gVar);
    }

    public static g valueOf(String str) {
        return (g) Enum.valueOf(g.class, str);
    }

    public static g[] values() {
        return (g[]) f2193f.clone();
    }
}
