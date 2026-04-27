package O1;

import kotlin.enums.EnumEntries;
import kotlin.jvm.internal.DefaultConstructorMarker;
import m2.AbstractC0628a;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* JADX INFO: loaded from: classes.dex */
public final class s {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f2136c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final s f2137d = new s("START", 0, "topTouchStart");

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final s f2138e = new s("END", 1, "topTouchEnd");

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final s f2139f = new s("MOVE", 2, "topTouchMove");

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final s f2140g = new s("CANCEL", 3, "topTouchCancel");

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final /* synthetic */ s[] f2141h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final /* synthetic */ EnumEntries f2142i;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f2143b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final String a(s sVar) {
            t2.j.f(sVar, "type");
            return sVar.c();
        }

        private a() {
        }
    }

    static {
        s[] sVarArrA = a();
        f2141h = sVarArrA;
        f2142i = AbstractC0628a.a(sVarArrA);
        f2136c = new a(null);
    }

    private s(String str, int i3, String str2) {
        this.f2143b = str2;
    }

    private static final /* synthetic */ s[] a() {
        return new s[]{f2137d, f2138e, f2139f, f2140g};
    }

    public static final String b(s sVar) {
        return f2136c.a(sVar);
    }

    public static s valueOf(String str) {
        return (s) Enum.valueOf(s.class, str);
    }

    public static s[] values() {
        return (s[]) f2141h.clone();
    }

    public final String c() {
        return this.f2143b;
    }
}
