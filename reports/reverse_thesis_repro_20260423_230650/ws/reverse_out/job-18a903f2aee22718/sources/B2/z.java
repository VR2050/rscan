package B2;

import B2.InterfaceC0167e;
import B2.r;
import L2.j;
import O2.c;
import i2.AbstractC0586n;
import java.net.Proxy;
import java.net.ProxySelector;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class z implements Cloneable, InterfaceC0167e.a {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private final int f465A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final int f466B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final int f467C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private final long f468D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private final G2.i f469E;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final p f470b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final k f471c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f472d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final List f473e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final r.c f474f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final boolean f475g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final InterfaceC0164b f476h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final boolean f477i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final boolean f478j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final n f479k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final C0165c f480l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final q f481m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final Proxy f482n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final ProxySelector f483o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final InterfaceC0164b f484p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final SocketFactory f485q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final SSLSocketFactory f486r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final X509TrustManager f487s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final List f488t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final List f489u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final HostnameVerifier f490v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private final C0169g f491w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private final O2.c f492x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private final int f493y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private final int f494z;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    public static final b f464H = new b(null);

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private static final List f462F = C2.c.t(A.HTTP_2, A.HTTP_1_1);

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private static final List f463G = C2.c.t(l.f353h, l.f355j);

    public static final class b {
        private b() {
        }

        public final List a() {
            return z.f463G;
        }

        public final List b() {
            return z.f462F;
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public z(a aVar) throws NoSuchAlgorithmException, KeyStoreException {
        ProxySelector proxySelectorH;
        t2.j.f(aVar, "builder");
        this.f470b = aVar.u();
        this.f471c = aVar.r();
        this.f472d = C2.c.R(aVar.A());
        this.f473e = C2.c.R(aVar.C());
        this.f474f = aVar.w();
        this.f475g = aVar.J();
        this.f476h = aVar.l();
        this.f477i = aVar.x();
        this.f478j = aVar.y();
        this.f479k = aVar.t();
        this.f480l = aVar.m();
        this.f481m = aVar.v();
        this.f482n = aVar.F();
        if (aVar.F() != null) {
            proxySelectorH = N2.a.f2018a;
        } else {
            proxySelectorH = aVar.H();
            proxySelectorH = proxySelectorH == null ? ProxySelector.getDefault() : proxySelectorH;
            if (proxySelectorH == null) {
                proxySelectorH = N2.a.f2018a;
            }
        }
        this.f483o = proxySelectorH;
        this.f484p = aVar.G();
        this.f485q = aVar.L();
        List listS = aVar.s();
        this.f488t = listS;
        this.f489u = aVar.E();
        this.f490v = aVar.z();
        this.f493y = aVar.n();
        this.f494z = aVar.q();
        this.f465A = aVar.I();
        this.f466B = aVar.N();
        this.f467C = aVar.D();
        this.f468D = aVar.B();
        G2.i iVarK = aVar.K();
        this.f469E = iVarK == null ? new G2.i() : iVarK;
        if (listS == null || !listS.isEmpty()) {
            Iterator it = listS.iterator();
            while (it.hasNext()) {
                if (((l) it.next()).f()) {
                    if (aVar.M() != null) {
                        this.f486r = aVar.M();
                        O2.c cVarO = aVar.o();
                        t2.j.c(cVarO);
                        this.f492x = cVarO;
                        X509TrustManager x509TrustManagerO = aVar.O();
                        t2.j.c(x509TrustManagerO);
                        this.f487s = x509TrustManagerO;
                        C0169g c0169gP = aVar.p();
                        t2.j.c(cVarO);
                        this.f491w = c0169gP.e(cVarO);
                    } else {
                        j.a aVar2 = L2.j.f1746c;
                        X509TrustManager x509TrustManagerP = aVar2.g().p();
                        this.f487s = x509TrustManagerP;
                        L2.j jVarG = aVar2.g();
                        t2.j.c(x509TrustManagerP);
                        this.f486r = jVarG.o(x509TrustManagerP);
                        c.a aVar3 = O2.c.f2150a;
                        t2.j.c(x509TrustManagerP);
                        O2.c cVarA = aVar3.a(x509TrustManagerP);
                        this.f492x = cVarA;
                        C0169g c0169gP2 = aVar.p();
                        t2.j.c(cVarA);
                        this.f491w = c0169gP2.e(cVarA);
                    }
                }
            }
            this.f486r = null;
            this.f492x = null;
            this.f487s = null;
            this.f491w = C0169g.f216c;
        } else {
            this.f486r = null;
            this.f492x = null;
            this.f487s = null;
            this.f491w = C0169g.f216c;
        }
        N();
    }

    private final void N() {
        List list = this.f472d;
        if (list == null) {
            throw new NullPointerException("null cannot be cast to non-null type kotlin.collections.List<okhttp3.Interceptor?>");
        }
        if (list.contains(null)) {
            throw new IllegalStateException(("Null interceptor: " + this.f472d).toString());
        }
        List list2 = this.f473e;
        if (list2 == null) {
            throw new NullPointerException("null cannot be cast to non-null type kotlin.collections.List<okhttp3.Interceptor?>");
        }
        if (list2.contains(null)) {
            throw new IllegalStateException(("Null network interceptor: " + this.f473e).toString());
        }
        List list3 = this.f488t;
        if (list3 == null || !list3.isEmpty()) {
            Iterator it = list3.iterator();
            while (it.hasNext()) {
                if (((l) it.next()).f()) {
                    if (this.f486r == null) {
                        throw new IllegalStateException("sslSocketFactory == null");
                    }
                    if (this.f492x == null) {
                        throw new IllegalStateException("certificateChainCleaner == null");
                    }
                    if (this.f487s == null) {
                        throw new IllegalStateException("x509TrustManager == null");
                    }
                    return;
                }
            }
        }
        if (!(this.f486r == null)) {
            throw new IllegalStateException("Check failed.");
        }
        if (!(this.f492x == null)) {
            throw new IllegalStateException("Check failed.");
        }
        if (!(this.f487s == null)) {
            throw new IllegalStateException("Check failed.");
        }
        if (!t2.j.b(this.f491w, C0169g.f216c)) {
            throw new IllegalStateException("Check failed.");
        }
    }

    public final long A() {
        return this.f468D;
    }

    public final List B() {
        return this.f473e;
    }

    public a C() {
        return new a(this);
    }

    public H D(B b3, I i3) {
        t2.j.f(b3, "request");
        t2.j.f(i3, "listener");
        P2.d dVar = new P2.d(F2.e.f751h, b3, i3, new Random(), this.f467C, null, this.f468D);
        dVar.p(this);
        return dVar;
    }

    public final int E() {
        return this.f467C;
    }

    public final List F() {
        return this.f489u;
    }

    public final Proxy G() {
        return this.f482n;
    }

    public final InterfaceC0164b H() {
        return this.f484p;
    }

    public final ProxySelector I() {
        return this.f483o;
    }

    public final int J() {
        return this.f465A;
    }

    public final boolean K() {
        return this.f475g;
    }

    public final SocketFactory L() {
        return this.f485q;
    }

    public final SSLSocketFactory M() {
        SSLSocketFactory sSLSocketFactory = this.f486r;
        if (sSLSocketFactory != null) {
            return sSLSocketFactory;
        }
        throw new IllegalStateException("CLEARTEXT-only client");
    }

    public final int O() {
        return this.f466B;
    }

    public final X509TrustManager P() {
        return this.f487s;
    }

    @Override // B2.InterfaceC0167e.a
    public InterfaceC0167e a(B b3) {
        t2.j.f(b3, "request");
        return new G2.e(this, b3, false);
    }

    public final p c() {
        return this.f470b;
    }

    public Object clone() {
        return super.clone();
    }

    public final InterfaceC0164b g() {
        return this.f476h;
    }

    public final C0165c h() {
        return this.f480l;
    }

    public final int j() {
        return this.f493y;
    }

    public final O2.c k() {
        return this.f492x;
    }

    public final C0169g l() {
        return this.f491w;
    }

    public final int m() {
        return this.f494z;
    }

    public final k n() {
        return this.f471c;
    }

    public final List o() {
        return this.f488t;
    }

    public final n q() {
        return this.f479k;
    }

    public final p s() {
        return this.f470b;
    }

    public final q t() {
        return this.f481m;
    }

    public final r.c u() {
        return this.f474f;
    }

    public final boolean v() {
        return this.f477i;
    }

    public final boolean w() {
        return this.f478j;
    }

    public final G2.i x() {
        return this.f469E;
    }

    public final HostnameVerifier y() {
        return this.f490v;
    }

    public final List z() {
        return this.f472d;
    }

    public static final class a {

        /* JADX INFO: renamed from: A, reason: collision with root package name */
        private int f495A;

        /* JADX INFO: renamed from: B, reason: collision with root package name */
        private int f496B;

        /* JADX INFO: renamed from: C, reason: collision with root package name */
        private long f497C;

        /* JADX INFO: renamed from: D, reason: collision with root package name */
        private G2.i f498D;

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private p f499a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private k f500b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final List f501c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final List f502d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private r.c f503e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f504f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private InterfaceC0164b f505g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private boolean f506h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private boolean f507i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private n f508j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private C0165c f509k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        private q f510l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        private Proxy f511m;

        /* JADX INFO: renamed from: n, reason: collision with root package name */
        private ProxySelector f512n;

        /* JADX INFO: renamed from: o, reason: collision with root package name */
        private InterfaceC0164b f513o;

        /* JADX INFO: renamed from: p, reason: collision with root package name */
        private SocketFactory f514p;

        /* JADX INFO: renamed from: q, reason: collision with root package name */
        private SSLSocketFactory f515q;

        /* JADX INFO: renamed from: r, reason: collision with root package name */
        private X509TrustManager f516r;

        /* JADX INFO: renamed from: s, reason: collision with root package name */
        private List f517s;

        /* JADX INFO: renamed from: t, reason: collision with root package name */
        private List f518t;

        /* JADX INFO: renamed from: u, reason: collision with root package name */
        private HostnameVerifier f519u;

        /* JADX INFO: renamed from: v, reason: collision with root package name */
        private C0169g f520v;

        /* JADX INFO: renamed from: w, reason: collision with root package name */
        private O2.c f521w;

        /* JADX INFO: renamed from: x, reason: collision with root package name */
        private int f522x;

        /* JADX INFO: renamed from: y, reason: collision with root package name */
        private int f523y;

        /* JADX INFO: renamed from: z, reason: collision with root package name */
        private int f524z;

        public a() {
            this.f499a = new p();
            this.f500b = new k();
            this.f501c = new ArrayList();
            this.f502d = new ArrayList();
            this.f503e = C2.c.e(r.f400a);
            this.f504f = true;
            InterfaceC0164b interfaceC0164b = InterfaceC0164b.f157a;
            this.f505g = interfaceC0164b;
            this.f506h = true;
            this.f507i = true;
            this.f508j = n.f388a;
            this.f510l = q.f398a;
            this.f513o = interfaceC0164b;
            SocketFactory socketFactory = SocketFactory.getDefault();
            t2.j.e(socketFactory, "SocketFactory.getDefault()");
            this.f514p = socketFactory;
            b bVar = z.f464H;
            this.f517s = bVar.a();
            this.f518t = bVar.b();
            this.f519u = O2.d.f2151a;
            this.f520v = C0169g.f216c;
            this.f523y = 10000;
            this.f524z = 10000;
            this.f495A = 10000;
            this.f497C = 1024L;
        }

        public final List A() {
            return this.f501c;
        }

        public final long B() {
            return this.f497C;
        }

        public final List C() {
            return this.f502d;
        }

        public final int D() {
            return this.f496B;
        }

        public final List E() {
            return this.f518t;
        }

        public final Proxy F() {
            return this.f511m;
        }

        public final InterfaceC0164b G() {
            return this.f513o;
        }

        public final ProxySelector H() {
            return this.f512n;
        }

        public final int I() {
            return this.f524z;
        }

        public final boolean J() {
            return this.f504f;
        }

        public final G2.i K() {
            return this.f498D;
        }

        public final SocketFactory L() {
            return this.f514p;
        }

        public final SSLSocketFactory M() {
            return this.f515q;
        }

        public final int N() {
            return this.f495A;
        }

        public final X509TrustManager O() {
            return this.f516r;
        }

        public final a P(HostnameVerifier hostnameVerifier) {
            t2.j.f(hostnameVerifier, "hostnameVerifier");
            if (!t2.j.b(hostnameVerifier, this.f519u)) {
                this.f498D = null;
            }
            this.f519u = hostnameVerifier;
            return this;
        }

        public final a Q(List list) {
            t2.j.f(list, "protocols");
            List listV = AbstractC0586n.V(list);
            A a3 = A.H2_PRIOR_KNOWLEDGE;
            if (!(listV.contains(a3) || listV.contains(A.HTTP_1_1))) {
                throw new IllegalArgumentException(("protocols must contain h2_prior_knowledge or http/1.1: " + listV).toString());
            }
            if (!(!listV.contains(a3) || listV.size() <= 1)) {
                throw new IllegalArgumentException(("protocols containing h2_prior_knowledge cannot use other protocols: " + listV).toString());
            }
            if (listV.contains(A.HTTP_1_0)) {
                throw new IllegalArgumentException(("protocols must not contain http/1.0: " + listV).toString());
            }
            if (listV.contains(null)) {
                throw new IllegalArgumentException("protocols must not contain null");
            }
            listV.remove(A.SPDY_3);
            if (!t2.j.b(listV, this.f518t)) {
                this.f498D = null;
            }
            List listUnmodifiableList = Collections.unmodifiableList(listV);
            t2.j.e(listUnmodifiableList, "Collections.unmodifiableList(protocolsCopy)");
            this.f518t = listUnmodifiableList;
            return this;
        }

        public final a R(Proxy proxy) {
            if (!t2.j.b(proxy, this.f511m)) {
                this.f498D = null;
            }
            this.f511m = proxy;
            return this;
        }

        public final a S(long j3, TimeUnit timeUnit) {
            t2.j.f(timeUnit, "unit");
            this.f524z = C2.c.h("timeout", j3, timeUnit);
            return this;
        }

        public final a T(boolean z3) {
            this.f504f = z3;
            return this;
        }

        public final a U(SocketFactory socketFactory) {
            t2.j.f(socketFactory, "socketFactory");
            if (socketFactory instanceof SSLSocketFactory) {
                throw new IllegalArgumentException("socketFactory instanceof SSLSocketFactory");
            }
            if (!t2.j.b(socketFactory, this.f514p)) {
                this.f498D = null;
            }
            this.f514p = socketFactory;
            return this;
        }

        public final a V(SSLSocketFactory sSLSocketFactory, X509TrustManager x509TrustManager) {
            t2.j.f(sSLSocketFactory, "sslSocketFactory");
            t2.j.f(x509TrustManager, "trustManager");
            if (!t2.j.b(sSLSocketFactory, this.f515q) || !t2.j.b(x509TrustManager, this.f516r)) {
                this.f498D = null;
            }
            this.f515q = sSLSocketFactory;
            this.f521w = O2.c.f2150a.a(x509TrustManager);
            this.f516r = x509TrustManager;
            return this;
        }

        public final a W(long j3, TimeUnit timeUnit) {
            t2.j.f(timeUnit, "unit");
            this.f495A = C2.c.h("timeout", j3, timeUnit);
            return this;
        }

        public final a a(v vVar) {
            t2.j.f(vVar, "interceptor");
            this.f501c.add(vVar);
            return this;
        }

        public final a b(v vVar) {
            t2.j.f(vVar, "interceptor");
            this.f502d.add(vVar);
            return this;
        }

        public final z c() {
            return new z(this);
        }

        public final a d(C0165c c0165c) {
            this.f509k = c0165c;
            return this;
        }

        public final a e(long j3, TimeUnit timeUnit) {
            t2.j.f(timeUnit, "unit");
            this.f522x = C2.c.h("timeout", j3, timeUnit);
            return this;
        }

        public final a f(long j3, TimeUnit timeUnit) {
            t2.j.f(timeUnit, "unit");
            this.f523y = C2.c.h("timeout", j3, timeUnit);
            return this;
        }

        public final a g(k kVar) {
            t2.j.f(kVar, "connectionPool");
            this.f500b = kVar;
            return this;
        }

        public final a h(n nVar) {
            t2.j.f(nVar, "cookieJar");
            this.f508j = nVar;
            return this;
        }

        public final a i(r rVar) {
            t2.j.f(rVar, "eventListener");
            this.f503e = C2.c.e(rVar);
            return this;
        }

        public final a j(boolean z3) {
            this.f506h = z3;
            return this;
        }

        public final a k(boolean z3) {
            this.f507i = z3;
            return this;
        }

        public final InterfaceC0164b l() {
            return this.f505g;
        }

        public final C0165c m() {
            return this.f509k;
        }

        public final int n() {
            return this.f522x;
        }

        public final O2.c o() {
            return this.f521w;
        }

        public final C0169g p() {
            return this.f520v;
        }

        public final int q() {
            return this.f523y;
        }

        public final k r() {
            return this.f500b;
        }

        public final List s() {
            return this.f517s;
        }

        public final n t() {
            return this.f508j;
        }

        public final p u() {
            return this.f499a;
        }

        public final q v() {
            return this.f510l;
        }

        public final r.c w() {
            return this.f503e;
        }

        public final boolean x() {
            return this.f506h;
        }

        public final boolean y() {
            return this.f507i;
        }

        public final HostnameVerifier z() {
            return this.f519u;
        }

        /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
        public a(z zVar) {
            this();
            t2.j.f(zVar, "okHttpClient");
            this.f499a = zVar.s();
            this.f500b = zVar.n();
            AbstractC0586n.q(this.f501c, zVar.z());
            AbstractC0586n.q(this.f502d, zVar.B());
            this.f503e = zVar.u();
            this.f504f = zVar.K();
            this.f505g = zVar.g();
            this.f506h = zVar.v();
            this.f507i = zVar.w();
            this.f508j = zVar.q();
            this.f509k = zVar.h();
            this.f510l = zVar.t();
            this.f511m = zVar.G();
            this.f512n = zVar.I();
            this.f513o = zVar.H();
            this.f514p = zVar.L();
            this.f515q = zVar.f486r;
            this.f516r = zVar.P();
            this.f517s = zVar.o();
            this.f518t = zVar.F();
            this.f519u = zVar.y();
            this.f520v = zVar.l();
            this.f521w = zVar.k();
            this.f522x = zVar.j();
            this.f523y = zVar.m();
            this.f524z = zVar.J();
            this.f495A = zVar.O();
            this.f496B = zVar.E();
            this.f497C = zVar.A();
            this.f498D = zVar.x();
        }
    }

    public z() {
        this(new a());
    }
}
