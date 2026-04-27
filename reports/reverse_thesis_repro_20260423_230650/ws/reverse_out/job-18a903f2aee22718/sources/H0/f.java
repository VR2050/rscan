package H0;

import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;
import t2.j;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class f {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f1014b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final f f1015c = new f("LOW", 0);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final f f1016d = new f("MEDIUM", 1);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final f f1017e = new f("HIGH", 2);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final /* synthetic */ f[] f1018f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f1019g;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final f a(f fVar, f fVar2) {
            j.f(fVar, "priority1");
            j.f(fVar2, "priority2");
            return fVar.ordinal() > fVar2.ordinal() ? fVar : fVar2;
        }

        private a() {
        }
    }

    static {
        f[] fVarArrA = a();
        f1018f = fVarArrA;
        f1019g = AbstractC0628a.a(fVarArrA);
        f1014b = new a(null);
    }

    private f(String str, int i3) {
    }

    private static final /* synthetic */ f[] a() {
        return new f[]{f1015c, f1016d, f1017e};
    }

    public static final f b(f fVar, f fVar2) {
        return f1014b.a(fVar, fVar2);
    }

    public static f valueOf(String str) {
        return (f) Enum.valueOf(f.class, str);
    }

    public static f[] values() {
        return (f[]) f1018f.clone();
    }
}
