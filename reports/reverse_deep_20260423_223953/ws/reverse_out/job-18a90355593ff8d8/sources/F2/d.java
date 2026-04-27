package F2;

import h2.r;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;
import java.util.logging.Level;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f745a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private a f746b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final List f747c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f748d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final e f749e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final String f750f;

    public d(e eVar, String str) {
        j.f(eVar, "taskRunner");
        j.f(str, "name");
        this.f749e = eVar;
        this.f750f = str;
        this.f747c = new ArrayList();
    }

    public static /* synthetic */ void j(d dVar, a aVar, long j3, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            j3 = 0;
        }
        dVar.i(aVar, j3);
    }

    public final void a() {
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
        synchronized (this.f749e) {
            try {
                if (b()) {
                    this.f749e.h(this);
                }
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean b() {
        a aVar = this.f746b;
        if (aVar != null) {
            j.c(aVar);
            if (aVar.a()) {
                this.f748d = true;
            }
        }
        boolean z3 = false;
        for (int size = this.f747c.size() - 1; size >= 0; size--) {
            if (((a) this.f747c.get(size)).a()) {
                a aVar2 = (a) this.f747c.get(size);
                if (e.f753j.a().isLoggable(Level.FINE)) {
                    b.c(aVar2, this, "canceled");
                }
                this.f747c.remove(size);
                z3 = true;
            }
        }
        return z3;
    }

    public final a c() {
        return this.f746b;
    }

    public final boolean d() {
        return this.f748d;
    }

    public final List e() {
        return this.f747c;
    }

    public final String f() {
        return this.f750f;
    }

    public final boolean g() {
        return this.f745a;
    }

    public final e h() {
        return this.f749e;
    }

    public final void i(a aVar, long j3) {
        j.f(aVar, "task");
        synchronized (this.f749e) {
            if (!this.f745a) {
                if (k(aVar, j3, false)) {
                    this.f749e.h(this);
                }
                r rVar = r.f9288a;
            } else if (aVar.a()) {
                if (e.f753j.a().isLoggable(Level.FINE)) {
                    b.c(aVar, this, "schedule canceled (queue is shutdown)");
                }
            } else {
                if (e.f753j.a().isLoggable(Level.FINE)) {
                    b.c(aVar, this, "schedule failed (queue is shutdown)");
                }
                throw new RejectedExecutionException();
            }
        }
    }

    public final boolean k(a aVar, long j3, boolean z3) {
        String str;
        j.f(aVar, "task");
        aVar.e(this);
        long jC = this.f749e.g().c();
        long j4 = jC + j3;
        int iIndexOf = this.f747c.indexOf(aVar);
        if (iIndexOf != -1) {
            if (aVar.c() <= j4) {
                if (e.f753j.a().isLoggable(Level.FINE)) {
                    b.c(aVar, this, "already scheduled");
                }
                return false;
            }
            this.f747c.remove(iIndexOf);
        }
        aVar.g(j4);
        if (e.f753j.a().isLoggable(Level.FINE)) {
            if (z3) {
                str = "run again after " + b.b(j4 - jC);
            } else {
                str = "scheduled after " + b.b(j4 - jC);
            }
            b.c(aVar, this, str);
        }
        Iterator it = this.f747c.iterator();
        int size = 0;
        while (true) {
            if (!it.hasNext()) {
                size = -1;
                break;
            }
            if (((a) it.next()).c() - jC > j3) {
                break;
            }
            size++;
        }
        if (size == -1) {
            size = this.f747c.size();
        }
        this.f747c.add(size, aVar);
        return size == 0;
    }

    public final void l(a aVar) {
        this.f746b = aVar;
    }

    public final void m(boolean z3) {
        this.f748d = z3;
    }

    public final void n() {
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
        synchronized (this.f749e) {
            try {
                this.f745a = true;
                if (b()) {
                    this.f749e.h(this);
                }
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public String toString() {
        return this.f750f;
    }
}
