package Q0;

/* JADX INFO: loaded from: classes.dex */
public final class h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final h f2366a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final int f2367b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static int f2368c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static volatile C0204g f2369d;

    static {
        h hVar = new h();
        f2366a = hVar;
        f2367b = hVar.b();
        f2368c = 384;
    }

    private h() {
    }

    public static final C0204g a() {
        if (f2369d == null) {
            synchronized (h.class) {
                try {
                    if (f2369d == null) {
                        f2369d = new C0204g(f2368c, f2367b);
                    }
                    h2.r rVar = h2.r.f9288a;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        C0204g c0204g = f2369d;
        t2.j.c(c0204g);
        return c0204g;
    }

    private final int b() {
        int iMin = (int) Math.min(Runtime.getRuntime().maxMemory(), 2147483647L);
        return ((long) iMin) > 16777216 ? (iMin / 4) * 3 : iMin / 2;
    }
}
