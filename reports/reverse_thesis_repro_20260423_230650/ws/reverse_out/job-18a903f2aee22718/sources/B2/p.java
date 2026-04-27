package B2;

import G2.e;
import i2.AbstractC0586n;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public final class p {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Runnable f393c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private ExecutorService f394d;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f391a = 64;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f392b = 5;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final ArrayDeque f395e = new ArrayDeque();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final ArrayDeque f396f = new ArrayDeque();

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final ArrayDeque f397g = new ArrayDeque();

    private final e.a e(String str) {
        for (e.a aVar : this.f396f) {
            if (t2.j.b(aVar.d(), str)) {
                return aVar;
            }
        }
        for (e.a aVar2 : this.f395e) {
            if (t2.j.b(aVar2.d(), str)) {
                return aVar2;
            }
        }
        return null;
    }

    private final void f(Deque deque, Object obj) {
        Runnable runnable;
        synchronized (this) {
            if (!deque.remove(obj)) {
                throw new AssertionError("Call wasn't in-flight!");
            }
            runnable = this.f393c;
            h2.r rVar = h2.r.f9288a;
        }
        if (i() || runnable == null) {
            return;
        }
        runnable.run();
    }

    private final boolean i() {
        int i3;
        boolean z3;
        if (C2.c.f585h && Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST NOT hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        ArrayList arrayList = new ArrayList();
        synchronized (this) {
            try {
                Iterator it = this.f395e.iterator();
                t2.j.e(it, "readyAsyncCalls.iterator()");
                while (it.hasNext()) {
                    e.a aVar = (e.a) it.next();
                    if (this.f396f.size() >= this.f391a) {
                        break;
                    }
                    if (aVar.c().get() < this.f392b) {
                        it.remove();
                        aVar.c().incrementAndGet();
                        t2.j.e(aVar, "asyncCall");
                        arrayList.add(aVar);
                        this.f396f.add(aVar);
                    }
                }
                z3 = l() > 0;
                h2.r rVar = h2.r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
        int size = arrayList.size();
        for (i3 = 0; i3 < size; i3++) {
            ((e.a) arrayList.get(i3)).a(d());
        }
        return z3;
    }

    public final ExecutorService a() {
        return d();
    }

    public final void b(e.a aVar) {
        e.a aVarE;
        t2.j.f(aVar, "call");
        synchronized (this) {
            try {
                this.f395e.add(aVar);
                if (!aVar.b().o() && (aVarE = e(aVar.d())) != null) {
                    aVar.e(aVarE);
                }
                h2.r rVar = h2.r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
        i();
    }

    public final synchronized void c(G2.e eVar) {
        t2.j.f(eVar, "call");
        this.f397g.add(eVar);
    }

    public final synchronized ExecutorService d() {
        ExecutorService executorService;
        try {
            if (this.f394d == null) {
                this.f394d = new ThreadPoolExecutor(0, Integer.MAX_VALUE, 60L, TimeUnit.SECONDS, new SynchronousQueue(), C2.c.K(C2.c.f586i + " Dispatcher", false));
            }
            executorService = this.f394d;
            t2.j.c(executorService);
        } catch (Throwable th) {
            throw th;
        }
        return executorService;
    }

    public final void g(e.a aVar) {
        t2.j.f(aVar, "call");
        aVar.c().decrementAndGet();
        f(this.f396f, aVar);
    }

    public final void h(G2.e eVar) {
        t2.j.f(eVar, "call");
        f(this.f397g, eVar);
    }

    public final synchronized List j() {
        List listUnmodifiableList;
        try {
            ArrayDeque arrayDeque = this.f395e;
            ArrayList arrayList = new ArrayList(AbstractC0586n.o(arrayDeque, 10));
            Iterator it = arrayDeque.iterator();
            while (it.hasNext()) {
                arrayList.add(((e.a) it.next()).b());
            }
            listUnmodifiableList = Collections.unmodifiableList(arrayList);
            t2.j.e(listUnmodifiableList, "Collections.unmodifiable…yncCalls.map { it.call })");
        } catch (Throwable th) {
            throw th;
        }
        return listUnmodifiableList;
    }

    public final synchronized List k() {
        List listUnmodifiableList;
        try {
            ArrayDeque arrayDeque = this.f397g;
            ArrayDeque arrayDeque2 = this.f396f;
            ArrayList arrayList = new ArrayList(AbstractC0586n.o(arrayDeque2, 10));
            Iterator it = arrayDeque2.iterator();
            while (it.hasNext()) {
                arrayList.add(((e.a) it.next()).b());
            }
            listUnmodifiableList = Collections.unmodifiableList(AbstractC0586n.M(arrayDeque, arrayList));
            t2.j.e(listUnmodifiableList, "Collections.unmodifiable…yncCalls.map { it.call })");
        } catch (Throwable th) {
            throw th;
        }
        return listUnmodifiableList;
    }

    public final synchronized int l() {
        return this.f396f.size() + this.f397g.size();
    }
}
