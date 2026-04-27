package j;

import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public class c extends e {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static volatile c f9354c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final Executor f9355d = new Executor() { // from class: j.a
        @Override // java.util.concurrent.Executor
        public final void execute(Runnable runnable) {
            c.g(runnable);
        }
    };

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final Executor f9356e = new Executor() { // from class: j.b
        @Override // java.util.concurrent.Executor
        public final void execute(Runnable runnable) {
            c.h(runnable);
        }
    };

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private e f9357a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final e f9358b;

    private c() {
        d dVar = new d();
        this.f9358b = dVar;
        this.f9357a = dVar;
    }

    public static c f() {
        if (f9354c != null) {
            return f9354c;
        }
        synchronized (c.class) {
            try {
                if (f9354c == null) {
                    f9354c = new c();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return f9354c;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void g(Runnable runnable) {
        f().c(runnable);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void h(Runnable runnable) {
        f().a(runnable);
    }

    @Override // j.e
    public void a(Runnable runnable) {
        this.f9357a.a(runnable);
    }

    @Override // j.e
    public boolean b() {
        return this.f9357a.b();
    }

    @Override // j.e
    public void c(Runnable runnable) {
        this.f9357a.c(runnable);
    }
}
