package h0;

import X.k;
import X.n;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: renamed from: h0.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0552h implements n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final List f9256a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f9257b;

    private C0552h(List list, boolean z3) {
        k.c(!list.isEmpty(), "List of suppliers is empty!");
        this.f9256a = list;
        this.f9257b = z3;
    }

    public static C0552h c(List list, boolean z3) {
        return new C0552h(list, z3);
    }

    @Override // X.n
    /* JADX INFO: renamed from: d, reason: merged with bridge method [inline-methods] */
    public InterfaceC0547c get() {
        return new a();
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C0552h) {
            return X.i.a(this.f9256a, ((C0552h) obj).f9256a);
        }
        return false;
    }

    public int hashCode() {
        return this.f9256a.hashCode();
    }

    public String toString() {
        return X.i.b(this).b("list", this.f9256a).toString();
    }

    /* JADX INFO: renamed from: h0.h$a */
    private class a extends AbstractC0545a {

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private ArrayList f9258h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private int f9259i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private int f9260j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private AtomicInteger f9261k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        private Throwable f9262l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        private Map f9263m;

        public a() {
            if (C0552h.this.f9257b) {
                return;
            }
            B();
        }

        private void A(InterfaceC0547c interfaceC0547c) {
            if (interfaceC0547c != null) {
                interfaceC0547c.close();
            }
        }

        private void B() {
            if (this.f9261k != null) {
                return;
            }
            synchronized (this) {
                try {
                    if (this.f9261k == null) {
                        this.f9261k = new AtomicInteger(0);
                        int size = C0552h.this.f9256a.size();
                        this.f9260j = size;
                        this.f9259i = size;
                        this.f9258h = new ArrayList(size);
                        for (int i3 = 0; i3 < size; i3++) {
                            InterfaceC0547c interfaceC0547c = (InterfaceC0547c) ((n) C0552h.this.f9256a.get(i3)).get();
                            this.f9258h.add(interfaceC0547c);
                            interfaceC0547c.h(new C0130a(i3), V.a.b());
                            if (!interfaceC0547c.d()) {
                            }
                        }
                    }
                } finally {
                }
            }
        }

        private synchronized InterfaceC0547c C(int i3) {
            InterfaceC0547c interfaceC0547c;
            ArrayList arrayList = this.f9258h;
            interfaceC0547c = null;
            if (arrayList != null && i3 < arrayList.size()) {
                interfaceC0547c = (InterfaceC0547c) this.f9258h.set(i3, null);
            }
            return interfaceC0547c;
        }

        private synchronized InterfaceC0547c D(int i3) {
            ArrayList arrayList;
            arrayList = this.f9258h;
            return (arrayList == null || i3 >= arrayList.size()) ? null : (InterfaceC0547c) this.f9258h.get(i3);
        }

        private synchronized InterfaceC0547c E() {
            return D(this.f9259i);
        }

        private void F() {
            Throwable th;
            if (this.f9261k.incrementAndGet() != this.f9260j || (th = this.f9262l) == null) {
                return;
            }
            r(th, this.f9263m);
        }

        private void G(int i3, InterfaceC0547c interfaceC0547c, boolean z3) {
            synchronized (this) {
                try {
                    int i4 = this.f9259i;
                    if (interfaceC0547c == D(i3) && i3 != this.f9259i) {
                        if (E() == null || (z3 && i3 < this.f9259i)) {
                            this.f9259i = i3;
                        } else {
                            i3 = i4;
                        }
                        while (i4 > i3) {
                            A(C(i4));
                            i4--;
                        }
                    }
                } finally {
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void H(int i3, InterfaceC0547c interfaceC0547c) {
            A(J(i3, interfaceC0547c));
            if (i3 == 0) {
                this.f9262l = interfaceC0547c.f();
                this.f9263m = interfaceC0547c.b();
            }
            F();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void I(int i3, InterfaceC0547c interfaceC0547c) {
            G(i3, interfaceC0547c, interfaceC0547c.e());
            if (interfaceC0547c == E()) {
                v(null, i3 == 0 && interfaceC0547c.e(), interfaceC0547c.b());
            }
            F();
        }

        private synchronized InterfaceC0547c J(int i3, InterfaceC0547c interfaceC0547c) {
            if (interfaceC0547c == E()) {
                return null;
            }
            if (interfaceC0547c != D(i3)) {
                return interfaceC0547c;
            }
            return C(i3);
        }

        @Override // h0.AbstractC0545a, h0.InterfaceC0547c
        public synchronized Object a() {
            InterfaceC0547c interfaceC0547cE;
            try {
                if (C0552h.this.f9257b) {
                    B();
                }
                interfaceC0547cE = E();
            } catch (Throwable th) {
                throw th;
            }
            return interfaceC0547cE != null ? interfaceC0547cE.a() : null;
        }

        @Override // h0.AbstractC0545a, h0.InterfaceC0547c
        public boolean close() {
            if (C0552h.this.f9257b) {
                B();
            }
            synchronized (this) {
                try {
                    if (!super.close()) {
                        return false;
                    }
                    ArrayList arrayList = this.f9258h;
                    this.f9258h = null;
                    if (arrayList == null) {
                        return true;
                    }
                    for (int i3 = 0; i3 < arrayList.size(); i3++) {
                        A((InterfaceC0547c) arrayList.get(i3));
                    }
                    return true;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        /* JADX WARN: Removed duplicated region for block: B:13:0x001d  */
        @Override // h0.AbstractC0545a, h0.InterfaceC0547c
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public synchronized boolean d() {
            /*
                r1 = this;
                monitor-enter(r1)
                h0.h r0 = h0.C0552h.this     // Catch: java.lang.Throwable -> Ld
                boolean r0 = h0.C0552h.a(r0)     // Catch: java.lang.Throwable -> Ld
                if (r0 == 0) goto Lf
                r1.B()     // Catch: java.lang.Throwable -> Ld
                goto Lf
            Ld:
                r0 = move-exception
                goto L20
            Lf:
                h0.c r0 = r1.E()     // Catch: java.lang.Throwable -> Ld
                if (r0 == 0) goto L1d
                boolean r0 = r0.d()     // Catch: java.lang.Throwable -> Ld
                if (r0 == 0) goto L1d
                r0 = 1
                goto L1e
            L1d:
                r0 = 0
            L1e:
                monitor-exit(r1)
                return r0
            L20:
                monitor-exit(r1)     // Catch: java.lang.Throwable -> Ld
                throw r0
            */
            throw new UnsupportedOperationException("Method not decompiled: h0.C0552h.a.d():boolean");
        }

        /* JADX INFO: renamed from: h0.h$a$a, reason: collision with other inner class name */
        private class C0130a implements InterfaceC0549e {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            private int f9265a;

            public C0130a(int i3) {
                this.f9265a = i3;
            }

            @Override // h0.InterfaceC0549e
            public void a(InterfaceC0547c interfaceC0547c) {
                if (interfaceC0547c.d()) {
                    a.this.I(this.f9265a, interfaceC0547c);
                } else if (interfaceC0547c.e()) {
                    a.this.H(this.f9265a, interfaceC0547c);
                }
            }

            @Override // h0.InterfaceC0549e
            public void b(InterfaceC0547c interfaceC0547c) {
                if (this.f9265a == 0) {
                    a.this.t(interfaceC0547c.g());
                }
            }

            @Override // h0.InterfaceC0549e
            public void c(InterfaceC0547c interfaceC0547c) {
                a.this.H(this.f9265a, interfaceC0547c);
            }

            @Override // h0.InterfaceC0549e
            public void d(InterfaceC0547c interfaceC0547c) {
            }
        }
    }
}
