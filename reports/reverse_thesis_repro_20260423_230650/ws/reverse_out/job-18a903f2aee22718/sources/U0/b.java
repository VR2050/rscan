package U0;

import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final b f2800a = new b();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2801b = new C0042b();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static c f2802c;

    public interface a {
    }

    /* JADX INFO: renamed from: U0.b$b, reason: collision with other inner class name */
    private static final class C0042b implements a {
    }

    public interface c {
        void a(String str);

        void b();

        boolean isTracing();
    }

    private b() {
    }

    public static final void a(String str) {
        j.f(str, "name");
        f2800a.c().a(str);
    }

    public static final void b() {
        f2800a.c().b();
    }

    private final c c() {
        U0.a aVar;
        c cVar = f2802c;
        if (cVar != null) {
            return cVar;
        }
        synchronized (b.class) {
            aVar = new U0.a();
            f2802c = aVar;
        }
        return aVar;
    }

    public static final boolean d() {
        return f2800a.c().isTracing();
    }
}
