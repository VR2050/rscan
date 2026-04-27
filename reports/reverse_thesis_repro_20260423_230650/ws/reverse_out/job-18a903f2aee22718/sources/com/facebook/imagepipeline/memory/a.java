package com.facebook.imagepipeline.memory;

import Q0.F;
import Q0.G;
import X.k;
import X.m;
import X.p;
import a0.InterfaceC0218d;
import a0.InterfaceC0220f;
import android.util.SparseArray;
import android.util.SparseIntArray;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public abstract class a implements InterfaceC0220f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Class f6047a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final InterfaceC0218d f6048b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final F f6049c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    final SparseArray f6050d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    final Set f6051e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f6052f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    final C0095a f6053g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    final C0095a f6054h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final G f6055i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f6056j;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.memory.a$a, reason: collision with other inner class name */
    static class C0095a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        int f6057a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        int f6058b;

        C0095a() {
        }

        public void a(int i3) {
            int i4;
            int i5 = this.f6058b;
            if (i5 < i3 || (i4 = this.f6057a) <= 0) {
                Y.a.N("com.facebook.imagepipeline.memory.BasePool.Counter", "Unexpected decrement of %d. Current numBytes = %d, count = %d", Integer.valueOf(i3), Integer.valueOf(this.f6058b), Integer.valueOf(this.f6057a));
            } else {
                this.f6057a = i4 - 1;
                this.f6058b = i5 - i3;
            }
        }

        public void b(int i3) {
            this.f6057a++;
            this.f6058b += i3;
        }
    }

    public static class b extends RuntimeException {
        public b(Object obj) {
            super("Invalid size: " + obj.toString());
        }
    }

    public static class c extends RuntimeException {
        public c(int i3, int i4, int i5, int i6) {
            super("Pool hard cap violation? Hard cap = " + i3 + " Used size = " + i4 + " Free size = " + i5 + " Request size = " + i6);
        }
    }

    public a(InterfaceC0218d interfaceC0218d, F f3, G g3) {
        this.f6047a = getClass();
        this.f6048b = (InterfaceC0218d) k.g(interfaceC0218d);
        F f4 = (F) k.g(f3);
        this.f6049c = f4;
        this.f6055i = (G) k.g(g3);
        this.f6050d = new SparseArray();
        if (f4.f2355f) {
            q();
        } else {
            u(new SparseIntArray(0));
        }
        this.f6051e = m.b();
        this.f6054h = new C0095a();
        this.f6053g = new C0095a();
    }

    private synchronized void h() {
        try {
            k.i(!s() || this.f6054h.f6058b == 0);
        } catch (Throwable th) {
            throw th;
        }
    }

    private void i(SparseIntArray sparseIntArray) {
        this.f6050d.clear();
        for (int i3 = 0; i3 < sparseIntArray.size(); i3++) {
            int iKeyAt = sparseIntArray.keyAt(i3);
            this.f6050d.put(iKeyAt, new com.facebook.imagepipeline.memory.b(o(iKeyAt), sparseIntArray.valueAt(i3), 0, this.f6049c.f2355f));
        }
    }

    private synchronized com.facebook.imagepipeline.memory.b l(int i3) {
        return (com.facebook.imagepipeline.memory.b) this.f6050d.get(i3);
    }

    private synchronized void q() {
        try {
            SparseIntArray sparseIntArray = this.f6049c.f2352c;
            if (sparseIntArray != null) {
                i(sparseIntArray);
                this.f6052f = false;
            } else {
                this.f6052f = true;
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    private synchronized void u(SparseIntArray sparseIntArray) {
        try {
            k.g(sparseIntArray);
            this.f6050d.clear();
            SparseIntArray sparseIntArray2 = this.f6049c.f2352c;
            if (sparseIntArray2 != null) {
                for (int i3 = 0; i3 < sparseIntArray2.size(); i3++) {
                    int iKeyAt = sparseIntArray2.keyAt(i3);
                    this.f6050d.put(iKeyAt, new com.facebook.imagepipeline.memory.b(o(iKeyAt), sparseIntArray2.valueAt(i3), sparseIntArray.get(iKeyAt, 0), this.f6049c.f2355f));
                }
                this.f6052f = false;
            } else {
                this.f6052f = true;
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    private void v() {
        if (Y.a.w(2)) {
            Y.a.B(this.f6047a, "Used = (%d, %d); Free = (%d, %d)", Integer.valueOf(this.f6053g.f6057a), Integer.valueOf(this.f6053g.f6058b), Integer.valueOf(this.f6054h.f6057a), Integer.valueOf(this.f6054h.f6058b));
        }
    }

    @Override // a0.InterfaceC0220f, b0.g
    public void a(Object obj) {
        k.g(obj);
        int iN = n(obj);
        int iO = o(iN);
        synchronized (this) {
            try {
                com.facebook.imagepipeline.memory.b bVarL = l(iN);
                if (!this.f6051e.remove(obj)) {
                    Y.a.k(this.f6047a, "release (free, value unrecognized) (object, size) = (%x, %s)", Integer.valueOf(System.identityHashCode(obj)), Integer.valueOf(iN));
                    j(obj);
                    this.f6055i.c(iO);
                } else if (bVarL == null || bVarL.f() || s() || !t(obj)) {
                    if (bVarL != null) {
                        bVarL.b();
                    }
                    if (Y.a.w(2)) {
                        Y.a.z(this.f6047a, "release (free) (object, size) = (%x, %s)", Integer.valueOf(System.identityHashCode(obj)), Integer.valueOf(iN));
                    }
                    j(obj);
                    this.f6053g.a(iO);
                    this.f6055i.c(iO);
                } else {
                    bVarL.h(obj);
                    this.f6054h.b(iO);
                    this.f6053g.a(iO);
                    this.f6055i.e(iO);
                    if (Y.a.w(2)) {
                        Y.a.z(this.f6047a, "release (reuse) (object, size) = (%x, %s)", Integer.valueOf(System.identityHashCode(obj)), Integer.valueOf(iN));
                    }
                }
                v();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    protected abstract Object f(int i3);

    synchronized boolean g(int i3) {
        if (this.f6056j) {
            return true;
        }
        F f3 = this.f6049c;
        int i4 = f3.f2350a;
        int i5 = this.f6053g.f6058b;
        if (i3 > i4 - i5) {
            this.f6055i.d();
            return false;
        }
        int i6 = f3.f2351b;
        if (i3 > i6 - (i5 + this.f6054h.f6058b)) {
            x(i6 - i3);
        }
        if (i3 <= i4 - (this.f6053g.f6058b + this.f6054h.f6058b)) {
            return true;
        }
        this.f6055i.d();
        return false;
    }

    @Override // a0.InterfaceC0220f
    public Object get(int i3) throws Throwable {
        Object objF;
        Object objP;
        h();
        int iM = m(i3);
        synchronized (this) {
            try {
                com.facebook.imagepipeline.memory.b bVarK = k(iM);
                if (bVarK != null && (objP = p(bVarK)) != null) {
                    k.i(this.f6051e.add(objP));
                    int iN = n(objP);
                    int iO = o(iN);
                    this.f6053g.b(iO);
                    this.f6054h.a(iO);
                    this.f6055i.b(iO);
                    v();
                    if (Y.a.w(2)) {
                        Y.a.z(this.f6047a, "get (reuse) (object, size) = (%x, %s)", Integer.valueOf(System.identityHashCode(objP)), Integer.valueOf(iN));
                    }
                    return objP;
                }
                int iO2 = o(iM);
                if (!g(iO2)) {
                    throw new c(this.f6049c.f2350a, this.f6053g.f6058b, this.f6054h.f6058b, iO2);
                }
                this.f6053g.b(iO2);
                if (bVarK != null) {
                    bVarK.e();
                }
                try {
                    objF = f(iM);
                } catch (Throwable th) {
                    synchronized (this) {
                        try {
                            this.f6053g.a(iO2);
                            com.facebook.imagepipeline.memory.b bVarK2 = k(iM);
                            if (bVarK2 != null) {
                                bVarK2.b();
                            }
                            p.c(th);
                            objF = null;
                        } finally {
                        }
                    }
                }
                synchronized (this) {
                    try {
                        k.i(this.f6051e.add(objF));
                        y();
                        this.f6055i.a(iO2);
                        v();
                        if (Y.a.w(2)) {
                            Y.a.z(this.f6047a, "get (alloc) (object, size) = (%x, %s)", Integer.valueOf(System.identityHashCode(objF)), Integer.valueOf(iM));
                        }
                    } finally {
                    }
                }
                return objF;
            } finally {
            }
        }
    }

    protected abstract void j(Object obj);

    synchronized com.facebook.imagepipeline.memory.b k(int i3) {
        try {
            com.facebook.imagepipeline.memory.b bVar = (com.facebook.imagepipeline.memory.b) this.f6050d.get(i3);
            if (bVar == null && this.f6052f) {
                if (Y.a.w(2)) {
                    Y.a.y(this.f6047a, "creating new bucket %s", Integer.valueOf(i3));
                }
                com.facebook.imagepipeline.memory.b bVarW = w(i3);
                this.f6050d.put(i3, bVarW);
                return bVarW;
            }
            return bVar;
        } finally {
        }
    }

    protected abstract int m(int i3);

    protected abstract int n(Object obj);

    protected abstract int o(int i3);

    protected synchronized Object p(com.facebook.imagepipeline.memory.b bVar) {
        return bVar.c();
    }

    protected void r() {
        this.f6048b.a(this);
        this.f6055i.f(this);
    }

    synchronized boolean s() {
        boolean z3;
        z3 = this.f6053g.f6058b + this.f6054h.f6058b > this.f6049c.f2351b;
        if (z3) {
            this.f6055i.g();
        }
        return z3;
    }

    protected boolean t(Object obj) {
        k.g(obj);
        return true;
    }

    com.facebook.imagepipeline.memory.b w(int i3) {
        return new com.facebook.imagepipeline.memory.b(o(i3), Integer.MAX_VALUE, 0, this.f6049c.f2355f);
    }

    synchronized void x(int i3) {
        try {
            int i4 = this.f6053g.f6058b;
            int i5 = this.f6054h.f6058b;
            int iMin = Math.min((i4 + i5) - i3, i5);
            if (iMin <= 0) {
                return;
            }
            if (Y.a.w(2)) {
                Y.a.A(this.f6047a, "trimToSize: TargetSize = %d; Initial Size = %d; Bytes to free = %d", Integer.valueOf(i3), Integer.valueOf(this.f6053g.f6058b + this.f6054h.f6058b), Integer.valueOf(iMin));
            }
            v();
            for (int i6 = 0; i6 < this.f6050d.size() && iMin > 0; i6++) {
                com.facebook.imagepipeline.memory.b bVar = (com.facebook.imagepipeline.memory.b) k.g((com.facebook.imagepipeline.memory.b) this.f6050d.valueAt(i6));
                while (iMin > 0) {
                    Object objG = bVar.g();
                    if (objG == null) {
                        break;
                    }
                    j(objG);
                    int i7 = bVar.f6059a;
                    iMin -= i7;
                    this.f6054h.a(i7);
                }
            }
            v();
            if (Y.a.w(2)) {
                Y.a.z(this.f6047a, "trimToSize: TargetSize = %d; Final Size = %d", Integer.valueOf(i3), Integer.valueOf(this.f6053g.f6058b + this.f6054h.f6058b));
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    synchronized void y() {
        if (s()) {
            x(this.f6049c.f2351b);
        }
    }

    public a(InterfaceC0218d interfaceC0218d, F f3, G g3, boolean z3) {
        this(interfaceC0218d, f3, g3);
        this.f6056j = z3;
    }
}
