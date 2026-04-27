package androidx.lifecycle;

import androidx.lifecycle.f;
import java.util.Map;
import k.b;

/* JADX INFO: loaded from: classes.dex */
public abstract class LiveData {

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    static final Object f5102k = new Object();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final Object f5103a = new Object();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private k.b f5104b = new k.b();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    int f5105c = 0;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f5106d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private volatile Object f5107e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    volatile Object f5108f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f5109g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f5110h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f5111i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final Runnable f5112j;

    class LifecycleBoundObserver extends androidx.lifecycle.LiveData.c implements i {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final k f5113e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ LiveData f5114f;

        @Override // androidx.lifecycle.i
        public void d(k kVar, f.a aVar) {
            f.b bVarB = this.f5113e.s().b();
            if (bVarB == f.b.DESTROYED) {
                this.f5114f.h(this.f5117a);
                return;
            }
            f.b bVar = null;
            while (bVar != bVarB) {
                h(j());
                bVar = bVarB;
                bVarB = this.f5113e.s().b();
            }
        }

        void i() {
            this.f5113e.s().c(this);
        }

        boolean j() {
            return this.f5113e.s().b().b(f.b.STARTED);
        }
    }

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            Object obj;
            synchronized (LiveData.this.f5103a) {
                obj = LiveData.this.f5108f;
                LiveData.this.f5108f = LiveData.f5102k;
            }
            LiveData.this.i(obj);
        }
    }

    private class b extends c {
        b(p pVar) {
            super(pVar);
        }

        @Override // androidx.lifecycle.LiveData.c
        boolean j() {
            return true;
        }
    }

    private abstract class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final p f5117a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        boolean f5118b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        int f5119c = -1;

        c(p pVar) {
            this.f5117a = pVar;
        }

        void h(boolean z3) {
            if (z3 == this.f5118b) {
                return;
            }
            this.f5118b = z3;
            LiveData.this.b(z3 ? 1 : -1);
            if (this.f5118b) {
                LiveData.this.d(this);
            }
        }

        void i() {
        }

        abstract boolean j();
    }

    public LiveData() {
        Object obj = f5102k;
        this.f5108f = obj;
        this.f5112j = new a();
        this.f5107e = obj;
        this.f5109g = -1;
    }

    static void a(String str) {
        if (j.c.f().b()) {
            return;
        }
        throw new IllegalStateException("Cannot invoke " + str + " on a background thread");
    }

    private void c(c cVar) {
        if (cVar.f5118b) {
            if (!cVar.j()) {
                cVar.h(false);
                return;
            }
            int i3 = cVar.f5119c;
            int i4 = this.f5109g;
            if (i3 >= i4) {
                return;
            }
            cVar.f5119c = i4;
            cVar.f5117a.a(this.f5107e);
        }
    }

    void b(int i3) {
        int i4 = this.f5105c;
        this.f5105c = i3 + i4;
        if (this.f5106d) {
            return;
        }
        this.f5106d = true;
        while (true) {
            try {
                int i5 = this.f5105c;
                if (i4 == i5) {
                    this.f5106d = false;
                    return;
                }
                boolean z3 = i4 == 0 && i5 > 0;
                boolean z4 = i4 > 0 && i5 == 0;
                if (z3) {
                    f();
                } else if (z4) {
                    g();
                }
                i4 = i5;
            } catch (Throwable th) {
                this.f5106d = false;
                throw th;
            }
        }
    }

    void d(c cVar) {
        if (this.f5110h) {
            this.f5111i = true;
            return;
        }
        this.f5110h = true;
        do {
            this.f5111i = false;
            if (cVar != null) {
                c(cVar);
                cVar = null;
            } else {
                b.d dVarE = this.f5104b.e();
                while (dVarE.hasNext()) {
                    c((c) ((Map.Entry) dVarE.next()).getValue());
                    if (this.f5111i) {
                        break;
                    }
                }
            }
        } while (this.f5111i);
        this.f5110h = false;
    }

    public void e(p pVar) {
        a("observeForever");
        b bVar = new b(pVar);
        c cVar = (c) this.f5104b.i(pVar, bVar);
        if (cVar instanceof LifecycleBoundObserver) {
            throw new IllegalArgumentException("Cannot add the same observer with different lifecycles");
        }
        if (cVar != null) {
            return;
        }
        bVar.h(true);
    }

    protected void f() {
    }

    protected void g() {
    }

    public void h(p pVar) {
        a("removeObserver");
        c cVar = (c) this.f5104b.j(pVar);
        if (cVar == null) {
            return;
        }
        cVar.i();
        cVar.h(false);
    }

    protected void i(Object obj) {
        a("setValue");
        this.f5109g++;
        this.f5107e = obj;
        d(null);
    }
}
