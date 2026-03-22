package p429g.p433b.p434a.p444f;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p429g.p433b.p434a.p435a.AbstractC4334a;
import p429g.p433b.p434a.p435a.InterfaceC4335b;
import p429g.p433b.p434a.p436b.InterfaceC4336a;
import p429g.p433b.p434a.p439e.p443d.C4345a;

/* renamed from: g.b.a.f.a */
/* loaded from: classes2.dex */
public final class C4346a<T> extends AbstractC4334a<T> implements InterfaceC4335b<T> {

    /* renamed from: c */
    public static final a[] f11200c = new a[0];

    /* renamed from: e */
    public static final a[] f11201e = new a[0];

    /* renamed from: h */
    public T f11204h;

    /* renamed from: i */
    public Throwable f11205i;

    /* renamed from: g */
    public final AtomicBoolean f11203g = new AtomicBoolean();

    /* renamed from: f */
    public final AtomicReference<a<T>[]> f11202f = new AtomicReference<>(f11200c);

    /* renamed from: g.b.a.f.a$a */
    public static final class a<T> extends AtomicReference<C4346a<T>> implements InterfaceC4336a {
        private static final long serialVersionUID = -7650903191002190468L;

        /* renamed from: c */
        public final InterfaceC4335b<? super T> f11206c;

        public a(InterfaceC4335b<? super T> interfaceC4335b, C4346a<T> c4346a) {
            this.f11206c = interfaceC4335b;
            lazySet(c4346a);
        }

        /* renamed from: a */
        public void m4916a() {
            C4346a<T> andSet = getAndSet(null);
            if (andSet != null) {
                andSet.m4915d(this);
            }
        }
    }

    @Override // p429g.p433b.p434a.p435a.InterfaceC4335b
    /* renamed from: a */
    public void mo4910a(InterfaceC4336a interfaceC4336a) {
        if (this.f11202f.get() == f11201e) {
            ((a) interfaceC4336a).m4916a();
        }
    }

    @Override // p429g.p433b.p434a.p435a.AbstractC4334a
    /* renamed from: c */
    public void mo4909c(InterfaceC4335b<? super T> interfaceC4335b) {
        boolean z;
        a<T> aVar = new a<>(interfaceC4335b, this);
        interfaceC4335b.mo4910a(aVar);
        while (true) {
            a<T>[] aVarArr = this.f11202f.get();
            if (aVarArr == f11201e) {
                z = false;
                break;
            }
            int length = aVarArr.length;
            a<T>[] aVarArr2 = new a[length + 1];
            System.arraycopy(aVarArr, 0, aVarArr2, 0, length);
            aVarArr2[length] = aVar;
            if (this.f11202f.compareAndSet(aVarArr, aVarArr2)) {
                z = true;
                break;
            }
        }
        if (z) {
            if (aVar.get() == null) {
                m4915d(aVar);
            }
        } else {
            Throwable th = this.f11205i;
            if (th != null) {
                interfaceC4335b.onError(th);
            } else {
                interfaceC4335b.onSuccess(this.f11204h);
            }
        }
    }

    /* renamed from: d */
    public void m4915d(a<T> aVar) {
        a<T>[] aVarArr;
        a<T>[] aVarArr2;
        do {
            aVarArr = this.f11202f.get();
            int length = aVarArr.length;
            if (length == 0) {
                return;
            }
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    i2 = -1;
                    break;
                } else if (aVarArr[i2] == aVar) {
                    break;
                } else {
                    i2++;
                }
            }
            if (i2 < 0) {
                return;
            }
            if (length == 1) {
                aVarArr2 = f11200c;
            } else {
                a<T>[] aVarArr3 = new a[length - 1];
                System.arraycopy(aVarArr, 0, aVarArr3, 0, i2);
                System.arraycopy(aVarArr, i2 + 1, aVarArr3, i2, (length - i2) - 1);
                aVarArr2 = aVarArr3;
            }
        } while (!this.f11202f.compareAndSet(aVarArr, aVarArr2));
    }

    @Override // p429g.p433b.p434a.p435a.InterfaceC4335b
    public void onError(Throwable th) {
        C4345a.m4914a(th, "onError called with a null Throwable.");
        if (!this.f11203g.compareAndSet(false, true)) {
            C2354n.m2481h1(th);
            return;
        }
        this.f11205i = th;
        for (a<T> aVar : this.f11202f.getAndSet(f11201e)) {
            aVar.f11206c.onError(th);
        }
    }

    @Override // p429g.p433b.p434a.p435a.InterfaceC4335b
    public void onSuccess(T t) {
        C4345a.m4914a(t, "onSuccess called with a null value.");
        if (this.f11203g.compareAndSet(false, true)) {
            this.f11204h = t;
            for (a<T> aVar : this.f11202f.getAndSet(f11201e)) {
                aVar.f11206c.onSuccess(t);
            }
        }
    }
}
