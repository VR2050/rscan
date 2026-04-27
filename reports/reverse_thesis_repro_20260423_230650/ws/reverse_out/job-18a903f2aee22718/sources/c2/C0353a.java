package c2;

import com.facebook.systrace.TraceListener;
import kotlin.enums.EnumEntries;
import m2.AbstractC0628a;
import t2.j;

/* JADX INFO: renamed from: c2.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0353a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0353a f5681a = new C0353a();

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    /* JADX INFO: renamed from: c2.a$a, reason: collision with other inner class name */
    public static final class EnumC0088a {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final EnumC0088a f5682c = new EnumC0088a("THREAD", 0, 't');

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public static final EnumC0088a f5683d = new EnumC0088a("PROCESS", 1, 'p');

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public static final EnumC0088a f5684e = new EnumC0088a("GLOBAL", 2, 'g');

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private static final /* synthetic */ EnumC0088a[] f5685f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private static final /* synthetic */ EnumEntries f5686g;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final char f5687b;

        static {
            EnumC0088a[] enumC0088aArrA = a();
            f5685f = enumC0088aArrA;
            f5686g = AbstractC0628a.a(enumC0088aArrA);
        }

        private EnumC0088a(String str, int i3, char c3) {
            this.f5687b = c3;
        }

        private static final /* synthetic */ EnumC0088a[] a() {
            return new EnumC0088a[]{f5682c, f5683d, f5684e};
        }

        public static EnumC0088a valueOf(String str) {
            return (EnumC0088a) Enum.valueOf(EnumC0088a.class, str);
        }

        public static EnumC0088a[] values() {
            return (EnumC0088a[]) f5685f.clone();
        }
    }

    private C0353a() {
    }

    public static final void a(long j3, String str, int i3) {
        j.f(str, "sectionName");
        I.a.a(str, i3);
    }

    public static final void b(long j3, String str, int i3, long j4) {
        j.f(str, "sectionName");
        a(j3, str, i3);
    }

    public static final void c(long j3, String str) {
        j.f(str, "sectionName");
        I.a.c(str);
    }

    public static final void d(long j3, String str, String[] strArr, int i3) {
        j.f(str, "sectionName");
        j.f(strArr, "args");
        I.a.c(str + "|" + f5681a.e(strArr, i3));
    }

    private final String e(String[] strArr, int i3) {
        StringBuilder sb = new StringBuilder();
        for (int i4 = 1; i4 < i3; i4 += 2) {
            String str = strArr[i4 - 1];
            String str2 = strArr[i4];
            sb.append(str);
            sb.append('=');
            sb.append(str2);
            if (i4 < i3 - 1) {
                sb.append(';');
            }
        }
        String string = sb.toString();
        j.e(string, "toString(...)");
        return string;
    }

    public static final void f(long j3, String str, int i3) {
        j.f(str, "sectionName");
        g(j3, str, i3);
    }

    public static final void g(long j3, String str, int i3) {
        j.f(str, "sectionName");
        I.a.d(str, i3);
    }

    public static final void h(long j3, String str, int i3, long j4) {
        j.f(str, "sectionName");
        g(j3, str, i3);
    }

    public static final void i(long j3) {
        I.a.f();
    }

    public static final boolean j(long j3) {
        return false;
    }

    public static final void l(long j3, String str, int i3) {
        j.f(str, "sectionName");
        a(j3, str, i3);
    }

    public static final void m(long j3, String str, int i3) {
        j.f(str, "counterName");
        I.a.j(str, i3);
    }

    public static final void o(long j3, String str, Runnable runnable) {
        j.f(str, "sectionName");
        j.f(runnable, "block");
        c(j3, str);
        try {
            runnable.run();
        } finally {
            i(j3);
        }
    }

    public static final void k(TraceListener traceListener) {
    }

    public static final void p(TraceListener traceListener) {
    }

    public static final void n(long j3, String str, EnumC0088a enumC0088a) {
    }
}
