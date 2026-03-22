package p005b.p199l.p200a.p201a.p248o1;

import android.annotation.SuppressLint;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.SystemClock;
import androidx.annotation.Nullable;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.a0 */
/* loaded from: classes.dex */
public final class C2281a0 implements InterfaceC2283b0 {

    /* renamed from: a */
    public static final c f5767a = new c(2, -9223372036854775807L, null);

    /* renamed from: b */
    public static final c f5768b = new c(3, -9223372036854775807L, null);

    /* renamed from: c */
    public final ExecutorService f5769c;

    /* renamed from: d */
    @Nullable
    public d<? extends e> f5770d;

    /* renamed from: e */
    @Nullable
    public IOException f5771e;

    /* renamed from: b.l.a.a.o1.a0$b */
    public interface b<T extends e> {
        /* renamed from: k */
        void mo1768k(T t, long j2, long j3, boolean z);

        /* renamed from: l */
        void mo1769l(T t, long j2, long j3);

        /* renamed from: s */
        c mo1775s(T t, long j2, long j3, IOException iOException, int i2);
    }

    /* renamed from: b.l.a.a.o1.a0$c */
    public static final class c {

        /* renamed from: a */
        public final int f5772a;

        /* renamed from: b */
        public final long f5773b;

        public c(int i2, long j2, a aVar) {
            this.f5772a = i2;
            this.f5773b = j2;
        }

        /* renamed from: a */
        public boolean m2187a() {
            int i2 = this.f5772a;
            return i2 == 0 || i2 == 1;
        }
    }

    @SuppressLint({"HandlerLeak"})
    /* renamed from: b.l.a.a.o1.a0$d */
    public final class d<T extends e> extends Handler implements Runnable {

        /* renamed from: c */
        public final int f5774c;

        /* renamed from: e */
        public final T f5775e;

        /* renamed from: f */
        public final long f5776f;

        /* renamed from: g */
        @Nullable
        public b<T> f5777g;

        /* renamed from: h */
        @Nullable
        public IOException f5778h;

        /* renamed from: i */
        public int f5779i;

        /* renamed from: j */
        @Nullable
        public volatile Thread f5780j;

        /* renamed from: k */
        public volatile boolean f5781k;

        /* renamed from: l */
        public volatile boolean f5782l;

        public d(Looper looper, T t, b<T> bVar, int i2, long j2) {
            super(looper);
            this.f5775e = t;
            this.f5777g = bVar;
            this.f5774c = i2;
            this.f5776f = j2;
        }

        /* renamed from: a */
        public void m2188a(boolean z) {
            this.f5782l = z;
            this.f5778h = null;
            if (hasMessages(0)) {
                removeMessages(0);
                if (!z) {
                    sendEmptyMessage(1);
                }
            } else {
                this.f5781k = true;
                this.f5775e.mo1783b();
                Thread thread = this.f5780j;
                if (thread != null) {
                    thread.interrupt();
                }
            }
            if (z) {
                C2281a0.this.f5770d = null;
                long elapsedRealtime = SystemClock.elapsedRealtime();
                b<T> bVar = this.f5777g;
                Objects.requireNonNull(bVar);
                bVar.mo1768k(this.f5775e, elapsedRealtime, elapsedRealtime - this.f5776f, true);
                this.f5777g = null;
            }
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* renamed from: b */
        public void m2189b(long j2) {
            C4195m.m4771I(C2281a0.this.f5770d == null);
            C2281a0 c2281a0 = C2281a0.this;
            c2281a0.f5770d = this;
            if (j2 > 0) {
                sendEmptyMessageDelayed(0, j2);
            } else {
                this.f5778h = null;
                c2281a0.f5769c.execute(this);
            }
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) {
            if (this.f5782l) {
                return;
            }
            int i2 = message.what;
            if (i2 == 0) {
                this.f5778h = null;
                C2281a0 c2281a0 = C2281a0.this;
                ExecutorService executorService = c2281a0.f5769c;
                d<? extends e> dVar = c2281a0.f5770d;
                Objects.requireNonNull(dVar);
                executorService.execute(dVar);
                return;
            }
            if (i2 == 4) {
                throw ((Error) message.obj);
            }
            C2281a0.this.f5770d = null;
            long elapsedRealtime = SystemClock.elapsedRealtime();
            long j2 = elapsedRealtime - this.f5776f;
            b<T> bVar = this.f5777g;
            Objects.requireNonNull(bVar);
            if (this.f5781k) {
                bVar.mo1768k(this.f5775e, elapsedRealtime, j2, false);
                return;
            }
            int i3 = message.what;
            if (i3 == 1) {
                bVar.mo1768k(this.f5775e, elapsedRealtime, j2, false);
                return;
            }
            if (i3 == 2) {
                try {
                    bVar.mo1769l(this.f5775e, elapsedRealtime, j2);
                    return;
                } catch (RuntimeException e2) {
                    C2281a0.this.f5771e = new h(e2);
                    return;
                }
            }
            if (i3 != 3) {
                return;
            }
            IOException iOException = (IOException) message.obj;
            this.f5778h = iOException;
            int i4 = this.f5779i + 1;
            this.f5779i = i4;
            c mo1775s = bVar.mo1775s(this.f5775e, elapsedRealtime, j2, iOException, i4);
            int i5 = mo1775s.f5772a;
            if (i5 == 3) {
                C2281a0.this.f5771e = this.f5778h;
            } else if (i5 != 2) {
                if (i5 == 1) {
                    this.f5779i = 1;
                }
                long j3 = mo1775s.f5773b;
                if (j3 == -9223372036854775807L) {
                    j3 = Math.min((this.f5779i - 1) * 1000, 5000);
                }
                m2189b(j3);
            }
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                this.f5780j = Thread.currentThread();
                if (!this.f5781k) {
                    C2354n.m2488k("load:" + this.f5775e.getClass().getSimpleName());
                    try {
                        this.f5775e.mo1782a();
                        C2354n.m2443X();
                    } catch (Throwable th) {
                        C2354n.m2443X();
                        throw th;
                    }
                }
                if (this.f5782l) {
                    return;
                }
                sendEmptyMessage(2);
            } catch (IOException e2) {
                if (this.f5782l) {
                    return;
                }
                obtainMessage(3, e2).sendToTarget();
            } catch (Error e3) {
                if (!this.f5782l) {
                    obtainMessage(4, e3).sendToTarget();
                }
                throw e3;
            } catch (InterruptedException unused) {
                C4195m.m4771I(this.f5781k);
                if (this.f5782l) {
                    return;
                }
                sendEmptyMessage(2);
            } catch (Exception e4) {
                if (this.f5782l) {
                    return;
                }
                obtainMessage(3, new h(e4)).sendToTarget();
            } catch (OutOfMemoryError e5) {
                if (this.f5782l) {
                    return;
                }
                obtainMessage(3, new h(e5)).sendToTarget();
            }
        }
    }

    /* renamed from: b.l.a.a.o1.a0$e */
    public interface e {
        /* renamed from: a */
        void mo1782a();

        /* renamed from: b */
        void mo1783b();
    }

    /* renamed from: b.l.a.a.o1.a0$f */
    public interface f {
        /* renamed from: h */
        void mo1765h();
    }

    /* renamed from: b.l.a.a.o1.a0$g */
    public static final class g implements Runnable {

        /* renamed from: c */
        public final f f5784c;

        public g(f fVar) {
            this.f5784c = fVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f5784c.mo1765h();
        }
    }

    /* renamed from: b.l.a.a.o1.a0$h */
    public static final class h extends IOException {
        /* JADX WARN: Illegal instructions before constructor call */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public h(java.lang.Throwable r3) {
            /*
                r2 = this;
                java.lang.String r0 = "Unexpected "
                java.lang.StringBuilder r0 = p005b.p131d.p132a.p133a.C1499a.m586H(r0)
                java.lang.Class r1 = r3.getClass()
                java.lang.String r1 = r1.getSimpleName()
                r0.append(r1)
                java.lang.String r1 = ": "
                r0.append(r1)
                java.lang.String r1 = r3.getMessage()
                r0.append(r1)
                java.lang.String r0 = r0.toString()
                r2.<init>(r0, r3)
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p248o1.C2281a0.h.<init>(java.lang.Throwable):void");
        }
    }

    public C2281a0(final String str) {
        int i2 = C2344d0.f6035a;
        this.f5769c = Executors.newSingleThreadExecutor(new ThreadFactory() { // from class: b.l.a.a.p1.d
            @Override // java.util.concurrent.ThreadFactory
            public final Thread newThread(Runnable runnable) {
                return new Thread(runnable, str);
            }
        });
    }

    /* renamed from: c */
    public static c m2179c(boolean z, long j2) {
        return new c(z ? 1 : 0, j2, null);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2283b0
    /* renamed from: a */
    public void mo2180a() {
        m2184f(Integer.MIN_VALUE);
    }

    /* renamed from: b */
    public void m2181b() {
        d<? extends e> dVar = this.f5770d;
        C4195m.m4775K(dVar);
        dVar.m2188a(false);
    }

    /* renamed from: d */
    public boolean m2182d() {
        return this.f5771e != null;
    }

    /* renamed from: e */
    public boolean m2183e() {
        return this.f5770d != null;
    }

    /* renamed from: f */
    public void m2184f(int i2) {
        IOException iOException = this.f5771e;
        if (iOException != null) {
            throw iOException;
        }
        d<? extends e> dVar = this.f5770d;
        if (dVar != null) {
            if (i2 == Integer.MIN_VALUE) {
                i2 = dVar.f5774c;
            }
            IOException iOException2 = dVar.f5778h;
            if (iOException2 != null && dVar.f5779i > i2) {
                throw iOException2;
            }
        }
    }

    /* renamed from: g */
    public void m2185g(@Nullable f fVar) {
        d<? extends e> dVar = this.f5770d;
        if (dVar != null) {
            dVar.m2188a(true);
        }
        if (fVar != null) {
            this.f5769c.execute(new g(fVar));
        }
        this.f5769c.shutdown();
    }

    /* renamed from: h */
    public <T extends e> long m2186h(T t, b<T> bVar, int i2) {
        Looper myLooper = Looper.myLooper();
        C4195m.m4775K(myLooper);
        this.f5771e = null;
        long elapsedRealtime = SystemClock.elapsedRealtime();
        new d(myLooper, t, bVar, i2, elapsedRealtime).m2189b(0L);
        return elapsedRealtime;
    }
}
