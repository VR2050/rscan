package com.facebook.imagepipeline.producers;

import android.util.Pair;
import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArraySet;

/* JADX INFO: loaded from: classes.dex */
public abstract class U implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final Map f6183a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final d0 f6184b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f6185c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final String f6186d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final String f6187e;

    class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Object f6188a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final CopyOnWriteArraySet f6189b = X.m.a();

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private Closeable f6190c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private float f6191d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f6192e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private C0360e f6193f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private b f6194g;

        /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.U$a$a, reason: collision with other inner class name */
        class C0096a extends AbstractC0361f {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ Pair f6196a;

            C0096a(Pair pair) {
                this.f6196a = pair;
            }

            @Override // com.facebook.imagepipeline.producers.f0
            public void a() {
                boolean zRemove;
                List list;
                C0360e c0360e;
                List listT;
                List listR;
                synchronized (a.this) {
                    try {
                        zRemove = a.this.f6189b.remove(this.f6196a);
                        list = null;
                        if (!zRemove) {
                            c0360e = null;
                            listT = null;
                        } else if (a.this.f6189b.isEmpty()) {
                            c0360e = a.this.f6193f;
                            listT = null;
                        } else {
                            List listS = a.this.s();
                            listT = a.this.t();
                            listR = a.this.r();
                            c0360e = null;
                            list = listS;
                        }
                        listR = listT;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                C0360e.f(list);
                C0360e.g(listT);
                C0360e.e(listR);
                if (c0360e != null) {
                    if (!U.this.f6185c || c0360e.v()) {
                        c0360e.j();
                    } else {
                        C0360e.g(c0360e.o(H0.f.f1015c));
                    }
                }
                if (zRemove) {
                    ((InterfaceC0369n) this.f6196a.first).b();
                }
            }

            @Override // com.facebook.imagepipeline.producers.AbstractC0361f, com.facebook.imagepipeline.producers.f0
            public void b() {
                C0360e.e(a.this.r());
            }

            @Override // com.facebook.imagepipeline.producers.AbstractC0361f, com.facebook.imagepipeline.producers.f0
            public void c() {
                C0360e.g(a.this.t());
            }

            @Override // com.facebook.imagepipeline.producers.AbstractC0361f, com.facebook.imagepipeline.producers.f0
            public void d() {
                C0360e.f(a.this.s());
            }
        }

        private class b extends AbstractC0358c {
            @Override // com.facebook.imagepipeline.producers.AbstractC0358c
            protected void g() {
                try {
                    if (U0.b.d()) {
                        U0.b.a("MultiplexProducer#onCancellation");
                    }
                    a.this.m(this);
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                } catch (Throwable th) {
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                    throw th;
                }
            }

            @Override // com.facebook.imagepipeline.producers.AbstractC0358c
            protected void h(Throwable th) {
                try {
                    if (U0.b.d()) {
                        U0.b.a("MultiplexProducer#onFailure");
                    }
                    a.this.n(this, th);
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                } catch (Throwable th2) {
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                    throw th2;
                }
            }

            @Override // com.facebook.imagepipeline.producers.AbstractC0358c
            protected void j(float f3) {
                try {
                    if (U0.b.d()) {
                        U0.b.a("MultiplexProducer#onProgressUpdate");
                    }
                    a.this.p(this, f3);
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                } catch (Throwable th) {
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                    throw th;
                }
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.facebook.imagepipeline.producers.AbstractC0358c
            /* JADX INFO: renamed from: p, reason: merged with bridge method [inline-methods] */
            public void i(Closeable closeable, int i3) {
                try {
                    if (U0.b.d()) {
                        U0.b.a("MultiplexProducer#onNewResult");
                    }
                    a.this.o(this, closeable, i3);
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                } catch (Throwable th) {
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                    throw th;
                }
            }

            private b() {
            }
        }

        public a(Object obj) {
            this.f6188a = obj;
        }

        private void g(Pair pair, e0 e0Var) {
            e0Var.Z(new C0096a(pair));
        }

        private void i(Closeable closeable) {
            if (closeable != null) {
                try {
                    closeable.close();
                } catch (IOException e3) {
                    throw new RuntimeException(e3);
                }
            }
        }

        private synchronized boolean j() {
            Iterator it = this.f6189b.iterator();
            while (it.hasNext()) {
                if (((e0) ((Pair) it.next()).second).d0()) {
                    return true;
                }
            }
            return false;
        }

        private synchronized boolean k() {
            Iterator it = this.f6189b.iterator();
            while (it.hasNext()) {
                if (!((e0) ((Pair) it.next()).second).v()) {
                    return false;
                }
            }
            return true;
        }

        private synchronized H0.f l() {
            H0.f fVarB;
            fVarB = H0.f.f1015c;
            Iterator it = this.f6189b.iterator();
            while (it.hasNext()) {
                fVarB = H0.f.b(fVarB, ((e0) ((Pair) it.next()).second).p());
            }
            return fVarB;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void q(f0.e eVar) {
            synchronized (this) {
                try {
                    X.k.b(Boolean.valueOf(this.f6193f == null));
                    X.k.b(Boolean.valueOf(this.f6194g == null));
                    if (this.f6189b.isEmpty()) {
                        U.this.k(this.f6188a, this);
                        return;
                    }
                    e0 e0Var = (e0) ((Pair) this.f6189b.iterator().next()).second;
                    C0360e c0360e = new C0360e(e0Var.W(), e0Var.getId(), e0Var.P(), e0Var.i(), e0Var.e0(), k(), j(), l(), e0Var.f0());
                    this.f6193f = c0360e;
                    c0360e.r(e0Var.b());
                    if (eVar.b()) {
                        this.f6193f.A("started_as_prefetch", Boolean.valueOf(eVar.a()));
                    }
                    b bVar = new b();
                    this.f6194g = bVar;
                    U.this.f6184b.a(bVar, this.f6193f);
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public synchronized List r() {
            C0360e c0360e = this.f6193f;
            if (c0360e == null) {
                return null;
            }
            return c0360e.m(j());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public synchronized List s() {
            C0360e c0360e = this.f6193f;
            if (c0360e == null) {
                return null;
            }
            return c0360e.n(k());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public synchronized List t() {
            C0360e c0360e = this.f6193f;
            if (c0360e == null) {
                return null;
            }
            return c0360e.o(l());
        }

        public boolean h(InterfaceC0369n interfaceC0369n, e0 e0Var) {
            Pair pairCreate = Pair.create(interfaceC0369n, e0Var);
            synchronized (this) {
                try {
                    if (U.this.i(this.f6188a) != this) {
                        return false;
                    }
                    this.f6189b.add(pairCreate);
                    List listS = s();
                    List listT = t();
                    List listR = r();
                    Closeable closeableG = this.f6190c;
                    float f3 = this.f6191d;
                    int i3 = this.f6192e;
                    C0360e.f(listS);
                    C0360e.g(listT);
                    C0360e.e(listR);
                    synchronized (pairCreate) {
                        try {
                            synchronized (this) {
                                if (closeableG != this.f6190c) {
                                    closeableG = null;
                                } else if (closeableG != null) {
                                    closeableG = U.this.g(closeableG);
                                }
                            }
                            if (closeableG != null) {
                                if (f3 > 0.0f) {
                                    interfaceC0369n.c(f3);
                                }
                                interfaceC0369n.d(closeableG, i3);
                                i(closeableG);
                            }
                        } catch (Throwable th) {
                            throw th;
                        } finally {
                        }
                    }
                    g(pairCreate, e0Var);
                    return true;
                } finally {
                }
            }
        }

        public void m(b bVar) {
            synchronized (this) {
                try {
                    if (this.f6194g != bVar) {
                        return;
                    }
                    this.f6194g = null;
                    this.f6193f = null;
                    i(this.f6190c);
                    this.f6190c = null;
                    q(f0.e.UNSET);
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        public void n(b bVar, Throwable th) {
            synchronized (this) {
                try {
                    if (this.f6194g != bVar) {
                        return;
                    }
                    this.f6189b.clear();
                    U.this.k(this.f6188a, this);
                    i(this.f6190c);
                    this.f6190c = null;
                    for (Pair pair : this.f6189b) {
                        synchronized (pair) {
                            try {
                                ((e0) pair.second).P().i((e0) pair.second, U.this.f6186d, th, null);
                                C0360e c0360e = this.f6193f;
                                if (c0360e != null) {
                                    ((e0) pair.second).r(c0360e.b());
                                }
                                ((InterfaceC0369n) pair.first).a(th);
                            } finally {
                            }
                        }
                    }
                } finally {
                }
            }
        }

        public void o(b bVar, Closeable closeable, int i3) {
            synchronized (this) {
                try {
                    if (this.f6194g != bVar) {
                        return;
                    }
                    i(this.f6190c);
                    this.f6190c = null;
                    int size = this.f6189b.size();
                    if (AbstractC0358c.f(i3)) {
                        this.f6190c = U.this.g(closeable);
                        this.f6192e = i3;
                    } else {
                        this.f6189b.clear();
                        U.this.k(this.f6188a, this);
                    }
                    for (Pair pair : this.f6189b) {
                        synchronized (pair) {
                            try {
                                if (AbstractC0358c.e(i3)) {
                                    ((e0) pair.second).P().d((e0) pair.second, U.this.f6186d, null);
                                    C0360e c0360e = this.f6193f;
                                    if (c0360e != null) {
                                        ((e0) pair.second).r(c0360e.b());
                                    }
                                    ((e0) pair.second).A(U.this.f6187e, Integer.valueOf(size));
                                }
                                ((InterfaceC0369n) pair.first).d(closeable, i3);
                            } finally {
                            }
                        }
                    }
                } finally {
                }
            }
        }

        public void p(b bVar, float f3) {
            synchronized (this) {
                try {
                    if (this.f6194g != bVar) {
                        return;
                    }
                    this.f6191d = f3;
                    for (Pair pair : this.f6189b) {
                        synchronized (pair) {
                            ((InterfaceC0369n) pair.first).c(f3);
                        }
                    }
                } finally {
                }
            }
        }
    }

    protected U(d0 d0Var, String str, String str2) {
        this(d0Var, str, str2, false);
    }

    private synchronized a h(Object obj) {
        a aVar;
        aVar = new a(obj);
        this.f6183a.put(obj, aVar);
        return aVar;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        a aVarI;
        boolean z3;
        try {
            if (U0.b.d()) {
                U0.b.a("MultiplexProducer#produceResults");
            }
            e0Var.P().g(e0Var, this.f6186d);
            Object objJ = j(e0Var);
            do {
                synchronized (this) {
                    try {
                        aVarI = i(objJ);
                        if (aVarI == null) {
                            aVarI = h(objJ);
                            z3 = true;
                        } else {
                            z3 = false;
                        }
                    } finally {
                    }
                }
            } while (!aVarI.h(interfaceC0369n, e0Var));
            if (z3) {
                aVarI.q(f0.e.c(e0Var.v()));
            }
            if (U0.b.d()) {
                U0.b.b();
            }
        } catch (Throwable th) {
            if (U0.b.d()) {
                U0.b.b();
            }
            throw th;
        }
    }

    protected abstract Closeable g(Closeable closeable);

    protected synchronized a i(Object obj) {
        return (a) this.f6183a.get(obj);
    }

    protected abstract Object j(e0 e0Var);

    protected synchronized void k(Object obj, a aVar) {
        if (this.f6183a.get(obj) == aVar) {
            this.f6183a.remove(obj);
        }
    }

    protected U(d0 d0Var, String str, String str2, boolean z3) {
        this.f6184b = d0Var;
        this.f6183a = new HashMap();
        this.f6185c = z3;
        this.f6186d = str;
        this.f6187e = str2;
    }
}
