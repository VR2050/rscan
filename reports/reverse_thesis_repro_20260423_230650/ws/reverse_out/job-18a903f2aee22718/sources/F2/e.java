package F2;

import h2.r;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class e {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final Logger f752i;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f754a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f755b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long f756c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f757d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final List f758e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Runnable f759f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final a f760g;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final b f753j = new b(null);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final e f751h = new e(new c(C2.c.K(C2.c.f586i + " TaskRunner", true)));

    public interface a {
        void a(e eVar, long j3);

        void b(e eVar);

        long c();

        void execute(Runnable runnable);
    }

    public static final class b {
        private b() {
        }

        public final Logger a() {
            return e.f752i;
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public static final class c implements a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final ThreadPoolExecutor f761a;

        public c(ThreadFactory threadFactory) {
            j.f(threadFactory, "threadFactory");
            this.f761a = new ThreadPoolExecutor(0, Integer.MAX_VALUE, 60L, TimeUnit.SECONDS, new SynchronousQueue(), threadFactory);
        }

        @Override // F2.e.a
        public void a(e eVar, long j3) throws InterruptedException {
            j.f(eVar, "taskRunner");
            long j4 = j3 / 1000000;
            long j5 = j3 - (1000000 * j4);
            if (j4 > 0 || j3 > 0) {
                eVar.wait(j4, (int) j5);
            }
        }

        @Override // F2.e.a
        public void b(e eVar) {
            j.f(eVar, "taskRunner");
            eVar.notify();
        }

        @Override // F2.e.a
        public long c() {
            return System.nanoTime();
        }

        @Override // F2.e.a
        public void execute(Runnable runnable) {
            j.f(runnable, "runnable");
            this.f761a.execute(runnable);
        }
    }

    public static final class d implements Runnable {
        d() {
        }

        @Override // java.lang.Runnable
        public void run() {
            F2.a aVarD;
            long jC;
            while (true) {
                synchronized (e.this) {
                    aVarD = e.this.d();
                }
                if (aVarD == null) {
                    return;
                }
                F2.d dVarD = aVarD.d();
                j.c(dVarD);
                boolean zIsLoggable = e.f753j.a().isLoggable(Level.FINE);
                if (zIsLoggable) {
                    jC = dVarD.h().g().c();
                    F2.b.c(aVarD, dVarD, "starting");
                } else {
                    jC = -1;
                }
                try {
                    try {
                        e.this.j(aVarD);
                        r rVar = r.f9288a;
                        if (zIsLoggable) {
                            F2.b.c(aVarD, dVarD, "finished run in " + F2.b.b(dVarD.h().g().c() - jC));
                        }
                    } finally {
                    }
                } catch (Throwable th) {
                    if (zIsLoggable) {
                        F2.b.c(aVarD, dVarD, "failed a run in " + F2.b.b(dVarD.h().g().c() - jC));
                    }
                    throw th;
                }
            }
        }
    }

    static {
        Logger logger = Logger.getLogger(e.class.getName());
        j.e(logger, "Logger.getLogger(TaskRunner::class.java.name)");
        f752i = logger;
    }

    public e(a aVar) {
        j.f(aVar, "backend");
        this.f760g = aVar;
        this.f754a = 10000;
        this.f757d = new ArrayList();
        this.f758e = new ArrayList();
        this.f759f = new d();
    }

    private final void c(F2.a aVar, long j3) {
        if (C2.c.f585h && !Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        F2.d dVarD = aVar.d();
        j.c(dVarD);
        if (!(dVarD.c() == aVar)) {
            throw new IllegalStateException("Check failed.");
        }
        boolean zD = dVarD.d();
        dVarD.m(false);
        dVarD.l(null);
        this.f757d.remove(dVarD);
        if (j3 != -1 && !zD && !dVarD.g()) {
            dVarD.k(aVar, j3, true);
        }
        if (dVarD.e().isEmpty()) {
            return;
        }
        this.f758e.add(dVarD);
    }

    private final void e(F2.a aVar) {
        if (!C2.c.f585h || Thread.holdsLock(this)) {
            aVar.g(-1L);
            F2.d dVarD = aVar.d();
            j.c(dVarD);
            dVarD.e().remove(aVar);
            this.f758e.remove(dVarD);
            dVarD.l(aVar);
            this.f757d.add(dVarD);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Thread ");
        Thread threadCurrentThread = Thread.currentThread();
        j.e(threadCurrentThread, "Thread.currentThread()");
        sb.append(threadCurrentThread.getName());
        sb.append(" MUST hold lock on ");
        sb.append(this);
        throw new AssertionError(sb.toString());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void j(F2.a aVar) {
        if (C2.c.f585h && Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST NOT hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        Thread threadCurrentThread2 = Thread.currentThread();
        j.e(threadCurrentThread2, "currentThread");
        String name = threadCurrentThread2.getName();
        threadCurrentThread2.setName(aVar.b());
        try {
            long jF = aVar.f();
            synchronized (this) {
                c(aVar, jF);
                r rVar = r.f9288a;
            }
            threadCurrentThread2.setName(name);
        } catch (Throwable th) {
            synchronized (this) {
                c(aVar, -1L);
                r rVar2 = r.f9288a;
                threadCurrentThread2.setName(name);
                throw th;
            }
        }
    }

    public final F2.a d() {
        boolean z3;
        if (C2.c.f585h && !Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        while (!this.f758e.isEmpty()) {
            long jC = this.f760g.c();
            Iterator it = this.f758e.iterator();
            long jMin = Long.MAX_VALUE;
            F2.a aVar = null;
            while (true) {
                if (!it.hasNext()) {
                    z3 = false;
                    break;
                }
                F2.a aVar2 = (F2.a) ((F2.d) it.next()).e().get(0);
                long jMax = Math.max(0L, aVar2.c() - jC);
                if (jMax > 0) {
                    jMin = Math.min(jMax, jMin);
                } else {
                    if (aVar != null) {
                        z3 = true;
                        break;
                    }
                    aVar = aVar2;
                }
            }
            if (aVar != null) {
                e(aVar);
                if (z3 || (!this.f755b && !this.f758e.isEmpty())) {
                    this.f760g.execute(this.f759f);
                }
                return aVar;
            }
            if (this.f755b) {
                if (jMin < this.f756c - jC) {
                    this.f760g.b(this);
                }
                return null;
            }
            this.f755b = true;
            this.f756c = jC + jMin;
            try {
                try {
                    this.f760g.a(this, jMin);
                } catch (InterruptedException unused) {
                    f();
                }
            } finally {
                this.f755b = false;
            }
        }
        return null;
    }

    public final void f() {
        for (int size = this.f757d.size() - 1; size >= 0; size--) {
            ((F2.d) this.f757d.get(size)).b();
        }
        for (int size2 = this.f758e.size() - 1; size2 >= 0; size2--) {
            F2.d dVar = (F2.d) this.f758e.get(size2);
            dVar.b();
            if (dVar.e().isEmpty()) {
                this.f758e.remove(size2);
            }
        }
    }

    public final a g() {
        return this.f760g;
    }

    public final void h(F2.d dVar) {
        j.f(dVar, "taskQueue");
        if (C2.c.f585h && !Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        if (dVar.c() == null) {
            if (dVar.e().isEmpty()) {
                this.f758e.remove(dVar);
            } else {
                C2.c.a(this.f758e, dVar);
            }
        }
        if (this.f755b) {
            this.f760g.b(this);
        } else {
            this.f760g.execute(this.f759f);
        }
    }

    public final F2.d i() {
        int i3;
        synchronized (this) {
            i3 = this.f754a;
            this.f754a = i3 + 1;
        }
        StringBuilder sb = new StringBuilder();
        sb.append('Q');
        sb.append(i3);
        return new F2.d(this, sb.toString());
    }
}
