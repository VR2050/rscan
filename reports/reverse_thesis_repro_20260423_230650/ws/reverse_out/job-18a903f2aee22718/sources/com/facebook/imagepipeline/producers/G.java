package com.facebook.imagepipeline.producers;

import android.os.SystemClock;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public class G {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f6117a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final d f6118b;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final int f6121e;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Runnable f6119c = new a();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Runnable f6120d = new b();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    N0.j f6122f = null;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    int f6123g = 0;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    f f6124h = f.IDLE;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    long f6125i = 0;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    long f6126j = 0;

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            G.this.d();
        }
    }

    class b implements Runnable {
        b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            G.this.j();
        }
    }

    static /* synthetic */ class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f6129a;

        static {
            int[] iArr = new int[f.values().length];
            f6129a = iArr;
            try {
                iArr[f.IDLE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f6129a[f.QUEUED.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f6129a[f.RUNNING.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f6129a[f.RUNNING_AND_PENDING.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    public interface d {
        void a(N0.j jVar, int i3);
    }

    static class e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private static ScheduledExecutorService f6130a;

        static ScheduledExecutorService a() {
            if (f6130a == null) {
                f6130a = Executors.newSingleThreadScheduledExecutor();
            }
            return f6130a;
        }
    }

    enum f {
        IDLE,
        QUEUED,
        RUNNING,
        RUNNING_AND_PENDING
    }

    public G(Executor executor, d dVar, int i3) {
        this.f6117a = executor;
        this.f6118b = dVar;
        this.f6121e = i3;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void d() {
        N0.j jVar;
        int i3;
        long jUptimeMillis = SystemClock.uptimeMillis();
        synchronized (this) {
            jVar = this.f6122f;
            i3 = this.f6123g;
            this.f6122f = null;
            this.f6123g = 0;
            this.f6124h = f.RUNNING;
            this.f6126j = jUptimeMillis;
        }
        try {
            if (i(jVar, i3)) {
                this.f6118b.a(jVar, i3);
            }
        } finally {
            N0.j.p(jVar);
            g();
        }
    }

    private void e(long j3) {
        Runnable runnableA = O0.a.a(this.f6120d, "JobScheduler_enqueueJob");
        if (j3 > 0) {
            e.a().schedule(runnableA, j3, TimeUnit.MILLISECONDS);
        } else {
            runnableA.run();
        }
    }

    private void g() {
        long jMax;
        boolean z3;
        long jUptimeMillis = SystemClock.uptimeMillis();
        synchronized (this) {
            try {
                if (this.f6124h == f.RUNNING_AND_PENDING) {
                    jMax = Math.max(this.f6126j + ((long) this.f6121e), jUptimeMillis);
                    this.f6125i = jUptimeMillis;
                    this.f6124h = f.QUEUED;
                    z3 = true;
                } else {
                    this.f6124h = f.IDLE;
                    jMax = 0;
                    z3 = false;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (z3) {
            e(jMax - jUptimeMillis);
        }
    }

    private static boolean i(N0.j jVar, int i3) {
        return AbstractC0358c.e(i3) || AbstractC0358c.n(i3, 4) || N0.j.w0(jVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void j() {
        this.f6117a.execute(O0.a.a(this.f6119c, "JobScheduler_submitJob"));
    }

    public void c() {
        N0.j jVar;
        synchronized (this) {
            jVar = this.f6122f;
            this.f6122f = null;
            this.f6123g = 0;
        }
        N0.j.p(jVar);
    }

    public synchronized long f() {
        return this.f6126j - this.f6125i;
    }

    public boolean h() {
        long jMax;
        long jUptimeMillis = SystemClock.uptimeMillis();
        synchronized (this) {
            try {
                boolean z3 = false;
                if (!i(this.f6122f, this.f6123g)) {
                    return false;
                }
                int i3 = c.f6129a[this.f6124h.ordinal()];
                if (i3 != 1) {
                    if (i3 == 3) {
                        this.f6124h = f.RUNNING_AND_PENDING;
                    }
                    jMax = 0;
                } else {
                    jMax = Math.max(this.f6126j + ((long) this.f6121e), jUptimeMillis);
                    this.f6125i = jUptimeMillis;
                    this.f6124h = f.QUEUED;
                    z3 = true;
                }
                if (z3) {
                    e(jMax - jUptimeMillis);
                }
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public boolean k(N0.j jVar, int i3) {
        N0.j jVar2;
        if (!i(jVar, i3)) {
            return false;
        }
        synchronized (this) {
            jVar2 = this.f6122f;
            this.f6122f = N0.j.i(jVar);
            this.f6123g = i3;
        }
        N0.j.p(jVar2);
        return true;
    }
}
