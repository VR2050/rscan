package B2;

import B2.t;
import i2.AbstractC0586n;
import java.io.Closeable;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class D implements Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private C0166d f104b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final B f105c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final A f106d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final String f107e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final int f108f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final s f109g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final t f110h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final E f111i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final D f112j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final D f113k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final D f114l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final long f115m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final long f116n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final G2.c f117o;

    public D(B b3, A a3, String str, int i3, s sVar, t tVar, E e3, D d3, D d4, D d5, long j3, long j4, G2.c cVar) {
        t2.j.f(b3, "request");
        t2.j.f(a3, "protocol");
        t2.j.f(str, "message");
        t2.j.f(tVar, "headers");
        this.f105c = b3;
        this.f106d = a3;
        this.f107e = str;
        this.f108f = i3;
        this.f109g = sVar;
        this.f110h = tVar;
        this.f111i = e3;
        this.f112j = d3;
        this.f113k = d4;
        this.f114l = d5;
        this.f115m = j3;
        this.f116n = j4;
        this.f117o = cVar;
    }

    public static /* synthetic */ String d0(D d3, String str, String str2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            str2 = null;
        }
        return d3.Z(str, str2);
    }

    public final int A() {
        return this.f108f;
    }

    public final G2.c D() {
        return this.f117o;
    }

    public final s P() {
        return this.f109g;
    }

    public final String W(String str) {
        return d0(this, str, null, 2, null);
    }

    public final String Z(String str, String str2) {
        t2.j.f(str, "name");
        String strA = this.f110h.a(str);
        return strA != null ? strA : str2;
    }

    public final E b() {
        return this.f111i;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        E e3 = this.f111i;
        if (e3 == null) {
            throw new IllegalStateException("response is not eligible for a body and must not be closed");
        }
        e3.close();
    }

    public final t e0() {
        return this.f110h;
    }

    public final boolean f0() {
        int i3 = this.f108f;
        return 200 <= i3 && 299 >= i3;
    }

    public final int i() {
        return this.f108f;
    }

    public final String n0() {
        return this.f107e;
    }

    public final t p() {
        return this.f110h;
    }

    public final E r() {
        return this.f111i;
    }

    public final D t0() {
        return this.f112j;
    }

    public String toString() {
        return "Response{protocol=" + this.f106d + ", code=" + this.f108f + ", message=" + this.f107e + ", url=" + this.f105c.l() + '}';
    }

    public final a u0() {
        return new a(this);
    }

    public final C0166d v() {
        C0166d c0166d = this.f104b;
        if (c0166d != null) {
            return c0166d;
        }
        C0166d c0166dB = C0166d.f194p.b(this.f110h);
        this.f104b = c0166dB;
        return c0166dB;
    }

    public final D v0() {
        return this.f114l;
    }

    public final A w0() {
        return this.f106d;
    }

    public final D x() {
        return this.f113k;
    }

    public final long x0() {
        return this.f116n;
    }

    public final List y() {
        String str;
        t tVar = this.f110h;
        int i3 = this.f108f;
        if (i3 == 401) {
            str = "WWW-Authenticate";
        } else {
            if (i3 != 407) {
                return AbstractC0586n.g();
            }
            str = "Proxy-Authenticate";
        }
        return H2.e.a(tVar, str);
    }

    public final B y0() {
        return this.f105c;
    }

    public final long z0() {
        return this.f115m;
    }

    public static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private B f118a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private A f119b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f120c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private String f121d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private s f122e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private t.a f123f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private E f124g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private D f125h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private D f126i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private D f127j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private long f128k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        private long f129l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        private G2.c f130m;

        public a() {
            this.f120c = -1;
            this.f123f = new t.a();
        }

        private final void e(D d3) {
            if (d3 != null) {
                if (!(d3.r() == null)) {
                    throw new IllegalArgumentException("priorResponse.body != null");
                }
            }
        }

        private final void f(String str, D d3) {
            if (d3 != null) {
                if (!(d3.r() == null)) {
                    throw new IllegalArgumentException((str + ".body != null").toString());
                }
                if (!(d3.t0() == null)) {
                    throw new IllegalArgumentException((str + ".networkResponse != null").toString());
                }
                if (!(d3.x() == null)) {
                    throw new IllegalArgumentException((str + ".cacheResponse != null").toString());
                }
                if (d3.v0() == null) {
                    return;
                }
                throw new IllegalArgumentException((str + ".priorResponse != null").toString());
            }
        }

        public a a(String str, String str2) {
            t2.j.f(str, "name");
            t2.j.f(str2, "value");
            this.f123f.a(str, str2);
            return this;
        }

        public a b(E e3) {
            this.f124g = e3;
            return this;
        }

        public D c() {
            int i3 = this.f120c;
            if (!(i3 >= 0)) {
                throw new IllegalStateException(("code < 0: " + this.f120c).toString());
            }
            B b3 = this.f118a;
            if (b3 == null) {
                throw new IllegalStateException("request == null");
            }
            A a3 = this.f119b;
            if (a3 == null) {
                throw new IllegalStateException("protocol == null");
            }
            String str = this.f121d;
            if (str != null) {
                return new D(b3, a3, str, i3, this.f122e, this.f123f.e(), this.f124g, this.f125h, this.f126i, this.f127j, this.f128k, this.f129l, this.f130m);
            }
            throw new IllegalStateException("message == null");
        }

        public a d(D d3) {
            f("cacheResponse", d3);
            this.f126i = d3;
            return this;
        }

        public a g(int i3) {
            this.f120c = i3;
            return this;
        }

        public final int h() {
            return this.f120c;
        }

        public a i(s sVar) {
            this.f122e = sVar;
            return this;
        }

        public a j(String str, String str2) {
            t2.j.f(str, "name");
            t2.j.f(str2, "value");
            this.f123f.i(str, str2);
            return this;
        }

        public a k(t tVar) {
            t2.j.f(tVar, "headers");
            this.f123f = tVar.e();
            return this;
        }

        public final void l(G2.c cVar) {
            t2.j.f(cVar, "deferredTrailers");
            this.f130m = cVar;
        }

        public a m(String str) {
            t2.j.f(str, "message");
            this.f121d = str;
            return this;
        }

        public a n(D d3) {
            f("networkResponse", d3);
            this.f125h = d3;
            return this;
        }

        public a o(D d3) {
            e(d3);
            this.f127j = d3;
            return this;
        }

        public a p(A a3) {
            t2.j.f(a3, "protocol");
            this.f119b = a3;
            return this;
        }

        public a q(long j3) {
            this.f129l = j3;
            return this;
        }

        public a r(B b3) {
            t2.j.f(b3, "request");
            this.f118a = b3;
            return this;
        }

        public a s(long j3) {
            this.f128k = j3;
            return this;
        }

        public a(D d3) {
            t2.j.f(d3, "response");
            this.f120c = -1;
            this.f118a = d3.y0();
            this.f119b = d3.w0();
            this.f120c = d3.A();
            this.f121d = d3.n0();
            this.f122e = d3.P();
            this.f123f = d3.e0().e();
            this.f124g = d3.r();
            this.f125h = d3.t0();
            this.f126i = d3.x();
            this.f127j = d3.v0();
            this.f128k = d3.z0();
            this.f129l = d3.x0();
            this.f130m = d3.D();
        }
    }
}
