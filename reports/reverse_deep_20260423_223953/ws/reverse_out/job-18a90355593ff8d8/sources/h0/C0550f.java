package h0;

import X.k;
import X.n;
import java.util.List;

/* JADX INFO: renamed from: h0.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0550f implements n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final List f9250a;

    /* JADX INFO: renamed from: h0.f$a */
    private class a extends AbstractC0545a {

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private int f9251h = 0;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private InterfaceC0547c f9252i = null;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private InterfaceC0547c f9253j = null;

        /* JADX INFO: renamed from: h0.f$a$a, reason: collision with other inner class name */
        private class C0129a implements InterfaceC0549e {
            @Override // h0.InterfaceC0549e
            public void a(InterfaceC0547c interfaceC0547c) {
                if (interfaceC0547c.d()) {
                    a.this.G(interfaceC0547c);
                } else if (interfaceC0547c.e()) {
                    a.this.F(interfaceC0547c);
                }
            }

            @Override // h0.InterfaceC0549e
            public void b(InterfaceC0547c interfaceC0547c) {
                a.this.t(Math.max(a.this.g(), interfaceC0547c.g()));
            }

            @Override // h0.InterfaceC0549e
            public void c(InterfaceC0547c interfaceC0547c) {
                a.this.F(interfaceC0547c);
            }

            private C0129a() {
            }

            @Override // h0.InterfaceC0549e
            public void d(InterfaceC0547c interfaceC0547c) {
            }
        }

        public a() {
            if (I()) {
                return;
            }
            q(new RuntimeException("No data source supplier or supplier returned null."));
        }

        private synchronized boolean A(InterfaceC0547c interfaceC0547c) {
            if (!l() && interfaceC0547c == this.f9252i) {
                this.f9252i = null;
                return true;
            }
            return false;
        }

        private void B(InterfaceC0547c interfaceC0547c) {
            if (interfaceC0547c != null) {
                interfaceC0547c.close();
            }
        }

        private synchronized InterfaceC0547c C() {
            return this.f9253j;
        }

        private synchronized n D() {
            if (l() || this.f9251h >= C0550f.this.f9250a.size()) {
                return null;
            }
            List list = C0550f.this.f9250a;
            int i3 = this.f9251h;
            this.f9251h = i3 + 1;
            return (n) list.get(i3);
        }

        private void E(InterfaceC0547c interfaceC0547c, boolean z3) {
            InterfaceC0547c interfaceC0547c2;
            synchronized (this) {
                if (interfaceC0547c == this.f9252i && interfaceC0547c != (interfaceC0547c2 = this.f9253j)) {
                    if (interfaceC0547c2 == null || z3) {
                        this.f9253j = interfaceC0547c;
                    } else {
                        interfaceC0547c2 = null;
                    }
                    B(interfaceC0547c2);
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void F(InterfaceC0547c interfaceC0547c) {
            if (A(interfaceC0547c)) {
                if (interfaceC0547c != C()) {
                    B(interfaceC0547c);
                }
                if (I()) {
                    return;
                }
                r(interfaceC0547c.f(), interfaceC0547c.b());
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void G(InterfaceC0547c interfaceC0547c) {
            E(interfaceC0547c, interfaceC0547c.e());
            if (interfaceC0547c == C()) {
                v(null, interfaceC0547c.e(), interfaceC0547c.b());
            }
        }

        private synchronized boolean H(InterfaceC0547c interfaceC0547c) {
            if (l()) {
                return false;
            }
            this.f9252i = interfaceC0547c;
            return true;
        }

        private boolean I() {
            n nVarD = D();
            InterfaceC0547c interfaceC0547c = nVarD != null ? (InterfaceC0547c) nVarD.get() : null;
            if (!H(interfaceC0547c) || interfaceC0547c == null) {
                B(interfaceC0547c);
                return false;
            }
            interfaceC0547c.h(new C0129a(), V.a.b());
            return true;
        }

        @Override // h0.AbstractC0545a, h0.InterfaceC0547c
        public synchronized Object a() {
            InterfaceC0547c interfaceC0547cC;
            interfaceC0547cC = C();
            return interfaceC0547cC != null ? interfaceC0547cC.a() : null;
        }

        @Override // h0.AbstractC0545a, h0.InterfaceC0547c
        public boolean close() {
            synchronized (this) {
                try {
                    if (!super.close()) {
                        return false;
                    }
                    InterfaceC0547c interfaceC0547c = this.f9252i;
                    this.f9252i = null;
                    InterfaceC0547c interfaceC0547c2 = this.f9253j;
                    this.f9253j = null;
                    B(interfaceC0547c2);
                    B(interfaceC0547c);
                    return true;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        /* JADX WARN: Removed duplicated region for block: B:10:0x0011  */
        @Override // h0.AbstractC0545a, h0.InterfaceC0547c
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public synchronized boolean d() {
            /*
                r1 = this;
                monitor-enter(r1)
                h0.c r0 = r1.C()     // Catch: java.lang.Throwable -> Lf
                if (r0 == 0) goto L11
                boolean r0 = r0.d()     // Catch: java.lang.Throwable -> Lf
                if (r0 == 0) goto L11
                r0 = 1
                goto L12
            Lf:
                r0 = move-exception
                goto L14
            L11:
                r0 = 0
            L12:
                monitor-exit(r1)
                return r0
            L14:
                monitor-exit(r1)     // Catch: java.lang.Throwable -> Lf
                throw r0
            */
            throw new UnsupportedOperationException("Method not decompiled: h0.C0550f.a.d():boolean");
        }
    }

    private C0550f(List list) {
        k.c(!list.isEmpty(), "List of suppliers is empty!");
        this.f9250a = list;
    }

    public static C0550f b(List list) {
        return new C0550f(list);
    }

    @Override // X.n
    /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
    public InterfaceC0547c get() {
        return new a();
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C0550f) {
            return X.i.a(this.f9250a, ((C0550f) obj).f9250a);
        }
        return false;
    }

    public int hashCode() {
        return this.f9250a.hashCode();
    }

    public String toString() {
        return X.i.b(this).b("list", this.f9250a).toString();
    }
}
