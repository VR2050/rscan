package B2;

import B2.B;
import B2.D;
import B2.t;
import E2.d;
import L2.j;
import Q2.l;
import i2.AbstractC0586n;
import i2.K;
import java.io.Closeable;
import java.io.File;
import java.io.Flushable;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import kotlin.jvm.internal.DefaultConstructorMarker;
import q2.AbstractC0663a;

/* JADX INFO: renamed from: B2.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0165c implements Closeable, Flushable {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final b f160h = new b(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final E2.d f161b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f162c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f163d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f164e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f165f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f166g;

    /* JADX INFO: renamed from: B2.c$a */
    private static final class a extends E {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Q2.k f167c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final d.C0015d f168d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final String f169e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final String f170f;

        /* JADX INFO: renamed from: B2.c$a$a, reason: collision with other inner class name */
        public static final class C0005a extends Q2.o {

            /* JADX INFO: renamed from: d, reason: collision with root package name */
            final /* synthetic */ Q2.F f172d;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            C0005a(Q2.F f3, Q2.F f4) {
                super(f4);
                this.f172d = f3;
            }

            @Override // Q2.o, Q2.F, java.io.Closeable, java.lang.AutoCloseable
            public void close() {
                a.this.D().close();
                super.close();
            }
        }

        public a(d.C0015d c0015d, String str, String str2) {
            t2.j.f(c0015d, "snapshot");
            this.f168d = c0015d;
            this.f169e = str;
            this.f170f = str2;
            Q2.F fI = c0015d.i(1);
            this.f167c = Q2.t.d(new C0005a(fI, fI));
        }

        public final d.C0015d D() {
            return this.f168d;
        }

        @Override // B2.E
        public long r() {
            String str = this.f170f;
            if (str != null) {
                return C2.c.T(str, -1L);
            }
            return -1L;
        }

        @Override // B2.E
        public x v() {
            String str = this.f169e;
            if (str != null) {
                return x.f437g.c(str);
            }
            return null;
        }

        @Override // B2.E
        public Q2.k y() {
            return this.f167c;
        }
    }

    /* JADX INFO: renamed from: B2.c$b */
    public static final class b {
        private b() {
        }

        private final Set d(t tVar) {
            int size = tVar.size();
            TreeSet treeSet = null;
            for (int i3 = 0; i3 < size; i3++) {
                if (z2.g.j("Vary", tVar.b(i3), true)) {
                    String strH = tVar.h(i3);
                    if (treeSet == null) {
                        treeSet = new TreeSet(z2.g.k(t2.w.f10219a));
                    }
                    for (String str : z2.g.f0(strH, new char[]{','}, false, 0, 6, null)) {
                        if (str == null) {
                            throw new NullPointerException("null cannot be cast to non-null type kotlin.CharSequence");
                        }
                        treeSet.add(z2.g.n0(str).toString());
                    }
                }
            }
            return treeSet != null ? treeSet : K.b();
        }

        private final t e(t tVar, t tVar2) {
            Set setD = d(tVar2);
            if (setD.isEmpty()) {
                return C2.c.f579b;
            }
            t.a aVar = new t.a();
            int size = tVar.size();
            for (int i3 = 0; i3 < size; i3++) {
                String strB = tVar.b(i3);
                if (setD.contains(strB)) {
                    aVar.a(strB, tVar.h(i3));
                }
            }
            return aVar.e();
        }

        public final boolean a(D d3) {
            t2.j.f(d3, "$this$hasVaryAll");
            return d(d3.e0()).contains("*");
        }

        public final String b(u uVar) {
            t2.j.f(uVar, "url");
            return Q2.l.f2556f.e(uVar.toString()).n().k();
        }

        public final int c(Q2.k kVar) throws IOException {
            t2.j.f(kVar, "source");
            try {
                long jU = kVar.U();
                String strH = kVar.H();
                if (jU >= 0 && jU <= Integer.MAX_VALUE && strH.length() <= 0) {
                    return (int) jU;
                }
                throw new IOException("expected an int but was \"" + jU + strH + '\"');
            } catch (NumberFormatException e3) {
                throw new IOException(e3.getMessage());
            }
        }

        public final t f(D d3) {
            t2.j.f(d3, "$this$varyHeaders");
            D dT0 = d3.t0();
            t2.j.c(dT0);
            return e(dT0.y0().e(), d3.e0());
        }

        public final boolean g(D d3, t tVar, B b3) {
            t2.j.f(d3, "cachedResponse");
            t2.j.f(tVar, "cachedRequest");
            t2.j.f(b3, "newRequest");
            Set<String> setD = d(d3.e0());
            if (setD != null && setD.isEmpty()) {
                return true;
            }
            for (String str : setD) {
                if (!t2.j.b(tVar.i(str), b3.f(str))) {
                    return false;
                }
            }
            return true;
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    /* JADX INFO: renamed from: B2.c$d */
    private final class d implements E2.b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Q2.D f186a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Q2.D f187b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private boolean f188c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final d.b f189d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ C0165c f190e;

        /* JADX INFO: renamed from: B2.c$d$a */
        public static final class a extends Q2.n {
            a(Q2.D d3) {
                super(d3);
            }

            @Override // Q2.n, Q2.D, java.io.Closeable, java.lang.AutoCloseable
            public void close() {
                synchronized (d.this.f190e) {
                    if (d.this.d()) {
                        return;
                    }
                    d.this.e(true);
                    C0165c c0165c = d.this.f190e;
                    c0165c.A(c0165c.r() + 1);
                    super.close();
                    d.this.f189d.b();
                }
            }
        }

        public d(C0165c c0165c, d.b bVar) {
            t2.j.f(bVar, "editor");
            this.f190e = c0165c;
            this.f189d = bVar;
            Q2.D dF = bVar.f(1);
            this.f186a = dF;
            this.f187b = new a(dF);
        }

        @Override // E2.b
        public Q2.D a() {
            return this.f187b;
        }

        @Override // E2.b
        public void b() {
            synchronized (this.f190e) {
                if (this.f188c) {
                    return;
                }
                this.f188c = true;
                C0165c c0165c = this.f190e;
                c0165c.y(c0165c.p() + 1);
                C2.c.j(this.f186a);
                try {
                    this.f189d.a();
                } catch (IOException unused) {
                }
            }
        }

        public final boolean d() {
            return this.f188c;
        }

        public final void e(boolean z3) {
            this.f188c = z3;
        }
    }

    public C0165c(File file, long j3, K2.a aVar) {
        t2.j.f(file, "directory");
        t2.j.f(aVar, "fileSystem");
        this.f161b = new E2.d(aVar, file, 201105, 2, j3, F2.e.f751h);
    }

    private final void b(d.b bVar) {
        if (bVar != null) {
            try {
                bVar.a();
            } catch (IOException unused) {
            }
        }
    }

    public final void A(int i3) {
        this.f162c = i3;
    }

    public final synchronized void D() {
        this.f165f++;
    }

    public final synchronized void P(E2.c cVar) {
        try {
            t2.j.f(cVar, "cacheStrategy");
            this.f166g++;
            if (cVar.b() != null) {
                this.f164e++;
            } else if (cVar.a() != null) {
                this.f165f++;
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final void W(D d3, D d4) {
        d.b bVarB;
        t2.j.f(d3, "cached");
        t2.j.f(d4, "network");
        C0006c c0006c = new C0006c(d4);
        E eR = d3.r();
        if (eR == null) {
            throw new NullPointerException("null cannot be cast to non-null type okhttp3.Cache.CacheResponseBody");
        }
        try {
            bVarB = ((a) eR).D().b();
            if (bVarB != null) {
                try {
                    c0006c.f(bVarB);
                    bVarB.b();
                } catch (IOException unused) {
                    b(bVarB);
                }
            }
        } catch (IOException unused2) {
            bVarB = null;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f161b.close();
    }

    @Override // java.io.Flushable
    public void flush() {
        this.f161b.flush();
    }

    public final D i(B b3) {
        t2.j.f(b3, "request");
        try {
            d.C0015d c0015dE0 = this.f161b.e0(f160h.b(b3.l()));
            if (c0015dE0 != null) {
                try {
                    C0006c c0006c = new C0006c(c0015dE0.i(0));
                    D d3 = c0006c.d(c0015dE0);
                    if (c0006c.b(b3, d3)) {
                        return d3;
                    }
                    E eR = d3.r();
                    if (eR != null) {
                        C2.c.j(eR);
                    }
                    return null;
                } catch (IOException unused) {
                    C2.c.j(c0015dE0);
                }
            }
        } catch (IOException unused2) {
        }
        return null;
    }

    public final int p() {
        return this.f163d;
    }

    public final int r() {
        return this.f162c;
    }

    public final E2.b v(D d3) {
        d.b bVarD0;
        t2.j.f(d3, "response");
        String strH = d3.y0().h();
        if (H2.f.f1078a.a(d3.y0().h())) {
            try {
                x(d3.y0());
            } catch (IOException unused) {
            }
            return null;
        }
        if (!t2.j.b(strH, "GET")) {
            return null;
        }
        b bVar = f160h;
        if (bVar.a(d3)) {
            return null;
        }
        C0006c c0006c = new C0006c(d3);
        try {
            bVarD0 = E2.d.d0(this.f161b, bVar.b(d3.y0().l()), 0L, 2, null);
            if (bVarD0 == null) {
                return null;
            }
            try {
                c0006c.f(bVarD0);
                return new d(this, bVarD0);
            } catch (IOException unused2) {
                b(bVarD0);
                return null;
            }
        } catch (IOException unused3) {
            bVarD0 = null;
        }
    }

    public final void x(B b3) {
        t2.j.f(b3, "request");
        this.f161b.C0(f160h.b(b3.l()));
    }

    public final void y(int i3) {
        this.f163d = i3;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C0165c(File file, long j3) {
        this(file, j3, K2.a.f1689a);
        t2.j.f(file, "directory");
    }

    /* JADX INFO: renamed from: B2.c$c, reason: collision with other inner class name */
    private static final class C0006c {

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private static final String f173k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        private static final String f174l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        public static final a f175m = new a(null);

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final String f176a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final t f177b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final String f178c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final A f179d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final int f180e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final String f181f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final t f182g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private final s f183h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final long f184i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private final long f185j;

        /* JADX INFO: renamed from: B2.c$c$a */
        public static final class a {
            private a() {
            }

            public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }
        }

        static {
            StringBuilder sb = new StringBuilder();
            j.a aVar = L2.j.f1746c;
            sb.append(aVar.g().g());
            sb.append("-Sent-Millis");
            f173k = sb.toString();
            f174l = aVar.g().g() + "-Received-Millis";
        }

        public C0006c(Q2.F f3) {
            t2.j.f(f3, "rawSource");
            try {
                Q2.k kVarD = Q2.t.d(f3);
                this.f176a = kVarD.H();
                this.f178c = kVarD.H();
                t.a aVar = new t.a();
                int iC = C0165c.f160h.c(kVarD);
                for (int i3 = 0; i3 < iC; i3++) {
                    aVar.b(kVarD.H());
                }
                this.f177b = aVar.e();
                H2.k kVarA = H2.k.f1094d.a(kVarD.H());
                this.f179d = kVarA.f1095a;
                this.f180e = kVarA.f1096b;
                this.f181f = kVarA.f1097c;
                t.a aVar2 = new t.a();
                int iC2 = C0165c.f160h.c(kVarD);
                for (int i4 = 0; i4 < iC2; i4++) {
                    aVar2.b(kVarD.H());
                }
                String str = f173k;
                String strF = aVar2.f(str);
                String str2 = f174l;
                String strF2 = aVar2.f(str2);
                aVar2.h(str);
                aVar2.h(str2);
                this.f184i = strF != null ? Long.parseLong(strF) : 0L;
                this.f185j = strF2 != null ? Long.parseLong(strF2) : 0L;
                this.f182g = aVar2.e();
                if (a()) {
                    String strH = kVarD.H();
                    if (strH.length() > 0) {
                        throw new IOException("expected \"\" but was \"" + strH + '\"');
                    }
                    this.f183h = s.f402e.a(!kVarD.K() ? G.f144i.a(kVarD.H()) : G.SSL_3_0, C0171i.f333s1.b(kVarD.H()), c(kVarD), c(kVarD));
                } else {
                    this.f183h = null;
                }
                f3.close();
            } catch (Throwable th) {
                f3.close();
                throw th;
            }
        }

        private final boolean a() {
            return z2.g.u(this.f176a, "https://", false, 2, null);
        }

        private final List c(Q2.k kVar) throws IOException {
            int iC = C0165c.f160h.c(kVar);
            if (iC == -1) {
                return AbstractC0586n.g();
            }
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                ArrayList arrayList = new ArrayList(iC);
                for (int i3 = 0; i3 < iC; i3++) {
                    String strH = kVar.H();
                    Q2.i iVar = new Q2.i();
                    Q2.l lVarB = Q2.l.f2556f.b(strH);
                    t2.j.c(lVarB);
                    iVar.z(lVarB);
                    arrayList.add(certificateFactory.generateCertificate(iVar.q0()));
                }
                return arrayList;
            } catch (CertificateException e3) {
                throw new IOException(e3.getMessage());
            }
        }

        private final void e(Q2.j jVar, List list) throws IOException {
            try {
                jVar.k0(list.size()).L(10);
                int size = list.size();
                for (int i3 = 0; i3 < size; i3++) {
                    byte[] encoded = ((Certificate) list.get(i3)).getEncoded();
                    l.a aVar = Q2.l.f2556f;
                    t2.j.e(encoded, "bytes");
                    jVar.j0(l.a.h(aVar, encoded, 0, 0, 3, null).a()).L(10);
                }
            } catch (CertificateEncodingException e3) {
                throw new IOException(e3.getMessage());
            }
        }

        public final boolean b(B b3, D d3) {
            t2.j.f(b3, "request");
            t2.j.f(d3, "response");
            return t2.j.b(this.f176a, b3.l().toString()) && t2.j.b(this.f178c, b3.h()) && C0165c.f160h.g(d3, this.f177b, b3);
        }

        public final D d(d.C0015d c0015d) {
            t2.j.f(c0015d, "snapshot");
            String strA = this.f182g.a("Content-Type");
            String strA2 = this.f182g.a("Content-Length");
            return new D.a().r(new B.a().m(this.f176a).g(this.f178c, null).f(this.f177b).b()).p(this.f179d).g(this.f180e).m(this.f181f).k(this.f182g).b(new a(c0015d, strA, strA2)).i(this.f183h).s(this.f184i).q(this.f185j).c();
        }

        public final void f(d.b bVar) throws IOException {
            t2.j.f(bVar, "editor");
            Q2.j jVarC = Q2.t.c(bVar.f(0));
            try {
                jVarC.j0(this.f176a).L(10);
                jVarC.j0(this.f178c).L(10);
                jVarC.k0(this.f177b.size()).L(10);
                int size = this.f177b.size();
                for (int i3 = 0; i3 < size; i3++) {
                    jVarC.j0(this.f177b.b(i3)).j0(": ").j0(this.f177b.h(i3)).L(10);
                }
                jVarC.j0(new H2.k(this.f179d, this.f180e, this.f181f).toString()).L(10);
                jVarC.k0(this.f182g.size() + 2).L(10);
                int size2 = this.f182g.size();
                for (int i4 = 0; i4 < size2; i4++) {
                    jVarC.j0(this.f182g.b(i4)).j0(": ").j0(this.f182g.h(i4)).L(10);
                }
                jVarC.j0(f173k).j0(": ").k0(this.f184i).L(10);
                jVarC.j0(f174l).j0(": ").k0(this.f185j).L(10);
                if (a()) {
                    jVarC.L(10);
                    s sVar = this.f183h;
                    t2.j.c(sVar);
                    jVarC.j0(sVar.a().c()).L(10);
                    e(jVarC, this.f183h.d());
                    e(jVarC, this.f183h.c());
                    jVarC.j0(this.f183h.e().a()).L(10);
                }
                h2.r rVar = h2.r.f9288a;
                AbstractC0663a.a(jVarC, null);
            } finally {
            }
        }

        public C0006c(D d3) {
            t2.j.f(d3, "response");
            this.f176a = d3.y0().l().toString();
            this.f177b = C0165c.f160h.f(d3);
            this.f178c = d3.y0().h();
            this.f179d = d3.w0();
            this.f180e = d3.A();
            this.f181f = d3.n0();
            this.f182g = d3.e0();
            this.f183h = d3.P();
            this.f184i = d3.z0();
            this.f185j = d3.x0();
        }
    }
}
