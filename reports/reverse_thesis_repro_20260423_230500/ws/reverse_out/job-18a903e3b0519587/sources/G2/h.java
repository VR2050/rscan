package G2;

import G2.e;
import h2.r;
import java.lang.ref.Reference;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class h {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final a f954f = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final long f955a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final F2.d f956b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final b f957c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final ConcurrentLinkedQueue f958d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final int f959e;

    public static final class a {
        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public static final class b extends F2.a {
        b(String str) {
            super(str, false, 2, null);
        }

        @Override // F2.a
        public long f() {
            return h.this.b(System.nanoTime());
        }
    }

    public h(F2.e eVar, int i3, long j3, TimeUnit timeUnit) {
        t2.j.f(eVar, "taskRunner");
        t2.j.f(timeUnit, "timeUnit");
        this.f959e = i3;
        this.f955a = timeUnit.toNanos(j3);
        this.f956b = eVar.i();
        this.f957c = new b(C2.c.f586i + " ConnectionPool");
        this.f958d = new ConcurrentLinkedQueue();
        if (j3 > 0) {
            return;
        }
        throw new IllegalArgumentException(("keepAliveDuration <= 0: " + j3).toString());
    }

    private final int d(f fVar, long j3) {
        if (C2.c.f585h && !Thread.holdsLock(fVar)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST hold lock on ");
            sb.append(fVar);
            throw new AssertionError(sb.toString());
        }
        List listN = fVar.n();
        int i3 = 0;
        while (i3 < listN.size()) {
            Reference reference = (Reference) listN.get(i3);
            if (reference.get() != null) {
                i3++;
            } else {
                L2.j.f1746c.g().m("A connection to " + fVar.A().a().l() + " was leaked. Did you forget to close a response body?", ((e.b) reference).a());
                listN.remove(i3);
                fVar.D(true);
                if (listN.isEmpty()) {
                    fVar.C(j3 - this.f955a);
                    return 0;
                }
            }
        }
        return listN.size();
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x002d A[Catch: all -> 0x002b, TryCatch #0 {all -> 0x002b, blocks: (B:8:0x0024, B:15:0x0033, B:13:0x002d, B:18:0x0037), top: B:26:0x0024 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean a(B2.C0163a r4, G2.e r5, java.util.List r6, boolean r7) {
        /*
            r3 = this;
            java.lang.String r0 = "address"
            t2.j.f(r4, r0)
            java.lang.String r0 = "call"
            t2.j.f(r5, r0)
            java.util.concurrent.ConcurrentLinkedQueue r0 = r3.f958d
            java.util.Iterator r0 = r0.iterator()
        L10:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L3f
            java.lang.Object r1 = r0.next()
            G2.f r1 = (G2.f) r1
            java.lang.String r2 = "connection"
            t2.j.e(r1, r2)
            monitor-enter(r1)
            if (r7 == 0) goto L2d
            boolean r2 = r1.v()     // Catch: java.lang.Throwable -> L2b
            if (r2 != 0) goto L2d
            goto L33
        L2b:
            r4 = move-exception
            goto L3d
        L2d:
            boolean r2 = r1.t(r4, r6)     // Catch: java.lang.Throwable -> L2b
            if (r2 != 0) goto L37
        L33:
            h2.r r2 = h2.r.f9288a     // Catch: java.lang.Throwable -> L2b
            monitor-exit(r1)
            goto L10
        L37:
            r5.d(r1)     // Catch: java.lang.Throwable -> L2b
            monitor-exit(r1)
            r4 = 1
            return r4
        L3d:
            monitor-exit(r1)
            throw r4
        L3f:
            r4 = 0
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: G2.h.a(B2.a, G2.e, java.util.List, boolean):boolean");
    }

    public final long b(long j3) {
        int i3 = 0;
        long j4 = Long.MIN_VALUE;
        f fVar = null;
        int i4 = 0;
        for (f fVar2 : this.f958d) {
            t2.j.e(fVar2, "connection");
            synchronized (fVar2) {
                try {
                    if (d(fVar2, j3) > 0) {
                        i4++;
                    } else {
                        i3++;
                        long jO = j3 - fVar2.o();
                        if (jO > j4) {
                            r rVar = r.f9288a;
                            fVar = fVar2;
                            j4 = jO;
                        } else {
                            r rVar2 = r.f9288a;
                        }
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        long j5 = this.f955a;
        if (j4 < j5 && i3 <= this.f959e) {
            if (i3 > 0) {
                return j5 - j4;
            }
            if (i4 > 0) {
                return j5;
            }
            return -1L;
        }
        t2.j.c(fVar);
        synchronized (fVar) {
            if (!fVar.n().isEmpty()) {
                return 0L;
            }
            if (fVar.o() + j4 != j3) {
                return 0L;
            }
            fVar.D(true);
            this.f958d.remove(fVar);
            C2.c.k(fVar.E());
            if (this.f958d.isEmpty()) {
                this.f956b.a();
            }
            return 0L;
        }
    }

    public final boolean c(f fVar) {
        t2.j.f(fVar, "connection");
        if (C2.c.f585h && !Thread.holdsLock(fVar)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST hold lock on ");
            sb.append(fVar);
            throw new AssertionError(sb.toString());
        }
        if (!fVar.p() && this.f959e != 0) {
            F2.d.j(this.f956b, this.f957c, 0L, 2, null);
            return false;
        }
        fVar.D(true);
        this.f958d.remove(fVar);
        if (this.f958d.isEmpty()) {
            this.f956b.a();
        }
        return true;
    }

    public final void e(f fVar) {
        t2.j.f(fVar, "connection");
        if (!C2.c.f585h || Thread.holdsLock(fVar)) {
            this.f958d.add(fVar);
            F2.d.j(this.f956b, this.f957c, 0L, 2, null);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Thread ");
        Thread threadCurrentThread = Thread.currentThread();
        t2.j.e(threadCurrentThread, "Thread.currentThread()");
        sb.append(threadCurrentThread.getName());
        sb.append(" MUST hold lock on ");
        sb.append(fVar);
        throw new AssertionError(sb.toString());
    }
}
