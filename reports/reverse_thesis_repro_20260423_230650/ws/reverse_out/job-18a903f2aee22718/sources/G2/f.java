package G2;

import B2.A;
import B2.B;
import B2.C0163a;
import B2.C0169g;
import B2.D;
import B2.F;
import B2.InterfaceC0167e;
import B2.l;
import B2.r;
import B2.s;
import B2.u;
import B2.z;
import J2.f;
import J2.m;
import J2.n;
import P2.d;
import Q2.G;
import Q2.t;
import i2.AbstractC0586n;
import java.io.IOException;
import java.net.ConnectException;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class f extends f.d implements B2.j {

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    public static final a f928t = new a(null);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Socket f929c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Socket f930d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private s f931e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private A f932f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private J2.f f933g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Q2.k f934h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private Q2.j f935i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f936j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f937k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private int f938l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f939m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private int f940n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private int f941o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final List f942p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private long f943q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final h f944r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final F f945s;

    public static final class a {
        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    static final class b extends t2.k implements InterfaceC0688a {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ C0169g f946c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ s f947d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ C0163a f948e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        b(C0169g c0169g, s sVar, C0163a c0163a) {
            super(0);
            this.f946c = c0169g;
            this.f947d = sVar;
            this.f948e = c0163a;
        }

        @Override // s2.InterfaceC0688a
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final List a() {
            O2.c cVarD = this.f946c.d();
            t2.j.c(cVarD);
            return cVarD.a(this.f947d.d(), this.f948e.l().h());
        }
    }

    static final class c extends t2.k implements InterfaceC0688a {
        c() {
            super(0);
        }

        @Override // s2.InterfaceC0688a
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final List a() {
            s sVar = f.this.f931e;
            t2.j.c(sVar);
            List<Certificate> listD = sVar.d();
            ArrayList arrayList = new ArrayList(AbstractC0586n.o(listD, 10));
            for (Certificate certificate : listD) {
                if (certificate == null) {
                    throw new NullPointerException("null cannot be cast to non-null type java.security.cert.X509Certificate");
                }
                arrayList.add((X509Certificate) certificate);
            }
            return arrayList;
        }
    }

    public static final class d extends d.AbstractC0035d {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ G2.c f950e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ Q2.k f951f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ Q2.j f952g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        d(G2.c cVar, Q2.k kVar, Q2.j jVar, boolean z3, Q2.k kVar2, Q2.j jVar2) {
            super(z3, kVar2, jVar2);
            this.f950e = cVar;
            this.f951f = kVar;
            this.f952g = jVar;
        }

        @Override // java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            this.f950e.a(-1L, true, true, null);
        }
    }

    public f(h hVar, F f3) {
        t2.j.f(hVar, "connectionPool");
        t2.j.f(f3, "route");
        this.f944r = hVar;
        this.f945s = f3;
        this.f941o = 1;
        this.f942p = new ArrayList();
        this.f943q = Long.MAX_VALUE;
    }

    private final boolean B(List list) {
        if (list != null && list.isEmpty()) {
            return false;
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            F f3 = (F) it.next();
            Proxy.Type type = f3.b().type();
            Proxy.Type type2 = Proxy.Type.DIRECT;
            if (type == type2 && this.f945s.b().type() == type2 && t2.j.b(this.f945s.d(), f3.d())) {
                return true;
            }
        }
        return false;
    }

    private final void F(int i3) throws SocketException {
        Socket socket = this.f930d;
        t2.j.c(socket);
        Q2.k kVar = this.f934h;
        t2.j.c(kVar);
        Q2.j jVar = this.f935i;
        t2.j.c(jVar);
        socket.setSoTimeout(0);
        J2.f fVarA = new f.b(true, F2.e.f751h).m(socket, this.f945s.a().l().h(), kVar, jVar).k(this).l(i3).a();
        this.f933g = fVarA;
        this.f941o = J2.f.f1512E.a().d();
        J2.f.W0(fVarA, false, null, 3, null);
    }

    private final boolean G(u uVar) {
        s sVar;
        if (C2.c.f585h && !Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        u uVarL = this.f945s.a().l();
        if (uVar.l() != uVarL.l()) {
            return false;
        }
        if (t2.j.b(uVar.h(), uVarL.h())) {
            return true;
        }
        if (this.f937k || (sVar = this.f931e) == null) {
            return false;
        }
        t2.j.c(sVar);
        return e(uVar, sVar);
    }

    private final boolean e(u uVar, s sVar) {
        List listD = sVar.d();
        if (listD.isEmpty()) {
            return false;
        }
        O2.d dVar = O2.d.f2151a;
        String strH = uVar.h();
        Object obj = listD.get(0);
        if (obj != null) {
            return dVar.e(strH, (X509Certificate) obj);
        }
        throw new NullPointerException("null cannot be cast to non-null type java.security.cert.X509Certificate");
    }

    private final void h(int i3, int i4, InterfaceC0167e interfaceC0167e, r rVar) throws IOException {
        Socket socket;
        int i5;
        Proxy proxyB = this.f945s.b();
        C0163a c0163aA = this.f945s.a();
        Proxy.Type type = proxyB.type();
        if (type != null && ((i5 = g.f953a[type.ordinal()]) == 1 || i5 == 2)) {
            socket = c0163aA.j().createSocket();
            t2.j.c(socket);
        } else {
            socket = new Socket(proxyB);
        }
        this.f929c = socket;
        rVar.j(interfaceC0167e, this.f945s.d(), proxyB);
        socket.setSoTimeout(i4);
        try {
            L2.j.f1746c.g().f(socket, this.f945s.d(), i3);
            try {
                this.f934h = t.d(t.m(socket));
                this.f935i = t.c(t.i(socket));
            } catch (NullPointerException e3) {
                if (t2.j.b(e3.getMessage(), "throw with null exception")) {
                    throw new IOException(e3);
                }
            }
        } catch (ConnectException e4) {
            ConnectException connectException = new ConnectException("Failed to connect to " + this.f945s.d());
            connectException.initCause(e4);
            throw connectException;
        }
    }

    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    private final void i(G2.b bVar) throws Throwable {
        C0163a c0163aA = this.f945s.a();
        SSLSocketFactory sSLSocketFactoryK = c0163aA.k();
        SSLSocket sSLSocket = null;
        try {
            t2.j.c(sSLSocketFactoryK);
            Socket socketCreateSocket = sSLSocketFactoryK.createSocket(this.f929c, c0163aA.l().h(), c0163aA.l().l(), true);
            if (socketCreateSocket == null) {
                throw new NullPointerException("null cannot be cast to non-null type javax.net.ssl.SSLSocket");
            }
            SSLSocket sSLSocket2 = (SSLSocket) socketCreateSocket;
            try {
                l lVarA = bVar.a(sSLSocket2);
                if (lVarA.h()) {
                    L2.j.f1746c.g().e(sSLSocket2, c0163aA.l().h(), c0163aA.f());
                }
                sSLSocket2.startHandshake();
                SSLSession session = sSLSocket2.getSession();
                s.a aVar = s.f402e;
                t2.j.e(session, "sslSocketSession");
                s sVarB = aVar.b(session);
                HostnameVerifier hostnameVerifierE = c0163aA.e();
                t2.j.c(hostnameVerifierE);
                if (hostnameVerifierE.verify(c0163aA.l().h(), session)) {
                    C0169g c0169gA = c0163aA.a();
                    t2.j.c(c0169gA);
                    this.f931e = new s(sVarB.e(), sVarB.a(), sVarB.c(), new b(c0169gA, sVarB, c0163aA));
                    c0169gA.b(c0163aA.l().h(), new c());
                    String strH = lVarA.h() ? L2.j.f1746c.g().h(sSLSocket2) : null;
                    this.f930d = sSLSocket2;
                    this.f934h = t.d(t.m(sSLSocket2));
                    this.f935i = t.c(t.i(sSLSocket2));
                    this.f932f = strH != null ? A.f84j.a(strH) : A.HTTP_1_1;
                    L2.j.f1746c.g().b(sSLSocket2);
                    return;
                }
                List listD = sVarB.d();
                if (listD.isEmpty()) {
                    throw new SSLPeerUnverifiedException("Hostname " + c0163aA.l().h() + " not verified (no certificates)");
                }
                Object obj = listD.get(0);
                if (obj == null) {
                    throw new NullPointerException("null cannot be cast to non-null type java.security.cert.X509Certificate");
                }
                X509Certificate x509Certificate = (X509Certificate) obj;
                StringBuilder sb = new StringBuilder();
                sb.append("\n              |Hostname ");
                sb.append(c0163aA.l().h());
                sb.append(" not verified:\n              |    certificate: ");
                sb.append(C0169g.f217d.a(x509Certificate));
                sb.append("\n              |    DN: ");
                Principal subjectDN = x509Certificate.getSubjectDN();
                t2.j.e(subjectDN, "cert.subjectDN");
                sb.append(subjectDN.getName());
                sb.append("\n              |    subjectAltNames: ");
                sb.append(O2.d.f2151a.a(x509Certificate));
                sb.append("\n              ");
                throw new SSLPeerUnverifiedException(z2.g.e(sb.toString(), null, 1, null));
            } catch (Throwable th) {
                th = th;
                sSLSocket = sSLSocket2;
                if (sSLSocket != null) {
                    L2.j.f1746c.g().b(sSLSocket);
                }
                if (sSLSocket != null) {
                    C2.c.k(sSLSocket);
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    private final void j(int i3, int i4, int i5, InterfaceC0167e interfaceC0167e, r rVar) throws IOException {
        B bL = l();
        u uVarL = bL.l();
        for (int i6 = 0; i6 < 21; i6++) {
            h(i3, i4, interfaceC0167e, rVar);
            bL = k(i4, i5, bL, uVarL);
            if (bL == null) {
                return;
            }
            Socket socket = this.f929c;
            if (socket != null) {
                C2.c.k(socket);
            }
            this.f929c = null;
            this.f935i = null;
            this.f934h = null;
            rVar.h(interfaceC0167e, this.f945s.d(), this.f945s.b(), null);
        }
    }

    private final B k(int i3, int i4, B b3, u uVar) throws IOException {
        String str = "CONNECT " + C2.c.P(uVar, true) + " HTTP/1.1";
        while (true) {
            Q2.k kVar = this.f934h;
            t2.j.c(kVar);
            Q2.j jVar = this.f935i;
            t2.j.c(jVar);
            I2.b bVar = new I2.b(null, this, kVar, jVar);
            TimeUnit timeUnit = TimeUnit.MILLISECONDS;
            kVar.f().g(i3, timeUnit);
            jVar.f().g(i4, timeUnit);
            bVar.A(b3.e(), str);
            bVar.c();
            D.a aVarG = bVar.g(false);
            t2.j.c(aVarG);
            D dC = aVarG.r(b3).c();
            bVar.z(dC);
            int iA = dC.A();
            if (iA == 200) {
                if (kVar.e().K() && jVar.e().K()) {
                    return null;
                }
                throw new IOException("TLS tunnel buffered too many bytes!");
            }
            if (iA != 407) {
                throw new IOException("Unexpected response code for CONNECT: " + dC.A());
            }
            B bA = this.f945s.a().h().a(this.f945s, dC);
            if (bA == null) {
                throw new IOException("Failed to authenticate with proxy");
            }
            if (z2.g.j("close", D.d0(dC, "Connection", null, 2, null), true)) {
                return bA;
            }
            b3 = bA;
        }
    }

    private final B l() {
        B b3 = new B.a().l(this.f945s.a().l()).g("CONNECT", null).e("Host", C2.c.P(this.f945s.a().l(), true)).e("Proxy-Connection", "Keep-Alive").e("User-Agent", "okhttp/4.9.2").b();
        B bA = this.f945s.a().h().a(this.f945s, new D.a().r(b3).p(A.HTTP_1_1).g(407).m("Preemptive Authenticate").b(C2.c.f580c).s(-1L).q(-1L).j("Proxy-Authenticate", "OkHttp-Preemptive").c());
        return bA != null ? bA : b3;
    }

    private final void m(G2.b bVar, int i3, InterfaceC0167e interfaceC0167e, r rVar) throws Throwable {
        if (this.f945s.a().k() != null) {
            rVar.C(interfaceC0167e);
            i(bVar);
            rVar.B(interfaceC0167e, this.f931e);
            if (this.f932f == A.HTTP_2) {
                F(i3);
                return;
            }
            return;
        }
        List listF = this.f945s.a().f();
        A a3 = A.H2_PRIOR_KNOWLEDGE;
        if (!listF.contains(a3)) {
            this.f930d = this.f929c;
            this.f932f = A.HTTP_1_1;
        } else {
            this.f930d = this.f929c;
            this.f932f = a3;
            F(i3);
        }
    }

    public F A() {
        return this.f945s;
    }

    public final void C(long j3) {
        this.f943q = j3;
    }

    public final void D(boolean z3) {
        this.f936j = z3;
    }

    public Socket E() {
        Socket socket = this.f930d;
        t2.j.c(socket);
        return socket;
    }

    public final synchronized void H(e eVar, IOException iOException) {
        try {
            t2.j.f(eVar, "call");
            if (iOException instanceof n) {
                if (((n) iOException).f1688b == J2.b.REFUSED_STREAM) {
                    int i3 = this.f940n + 1;
                    this.f940n = i3;
                    if (i3 > 1) {
                        this.f936j = true;
                        this.f938l++;
                    }
                } else if (((n) iOException).f1688b != J2.b.CANCEL || !eVar.r()) {
                    this.f936j = true;
                    this.f938l++;
                }
            } else if (!v() || (iOException instanceof J2.a)) {
                this.f936j = true;
                if (this.f939m == 0) {
                    if (iOException != null) {
                        g(eVar.l(), this.f945s, iOException);
                    }
                    this.f938l++;
                }
            }
        } finally {
        }
    }

    @Override // J2.f.d
    public synchronized void a(J2.f fVar, m mVar) {
        t2.j.f(fVar, "connection");
        t2.j.f(mVar, "settings");
        this.f941o = mVar.d();
    }

    @Override // J2.f.d
    public void b(J2.i iVar) {
        t2.j.f(iVar, "stream");
        iVar.d(J2.b.REFUSED_STREAM, null);
    }

    public final void d() {
        Socket socket = this.f929c;
        if (socket != null) {
            C2.c.k(socket);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x010a  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0111  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x013b  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0141  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0146  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x014e A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(int r17, int r18, int r19, int r20, boolean r21, B2.InterfaceC0167e r22, B2.r r23) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 356
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: G2.f.f(int, int, int, int, boolean, B2.e, B2.r):void");
    }

    public final void g(z zVar, F f3, IOException iOException) {
        t2.j.f(zVar, "client");
        t2.j.f(f3, "failedRoute");
        t2.j.f(iOException, "failure");
        if (f3.b().type() != Proxy.Type.DIRECT) {
            C0163a c0163aA = f3.a();
            c0163aA.i().connectFailed(c0163aA.l().q(), f3.b().address(), iOException);
        }
        zVar.x().b(f3);
    }

    public final List n() {
        return this.f942p;
    }

    public final long o() {
        return this.f943q;
    }

    public final boolean p() {
        return this.f936j;
    }

    public final int q() {
        return this.f938l;
    }

    public s r() {
        return this.f931e;
    }

    public final synchronized void s() {
        this.f939m++;
    }

    public final boolean t(C0163a c0163a, List list) {
        t2.j.f(c0163a, "address");
        if (C2.c.f585h && !Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        if (this.f942p.size() >= this.f941o || this.f936j || !this.f945s.a().d(c0163a)) {
            return false;
        }
        if (t2.j.b(c0163a.l().h(), A().a().l().h())) {
            return true;
        }
        if (this.f933g == null || list == null || !B(list) || c0163a.e() != O2.d.f2151a || !G(c0163a.l())) {
            return false;
        }
        try {
            C0169g c0169gA = c0163a.a();
            t2.j.c(c0169gA);
            String strH = c0163a.l().h();
            s sVarR = r();
            t2.j.c(sVarR);
            c0169gA.a(strH, sVarR.d());
            return true;
        } catch (SSLPeerUnverifiedException unused) {
            return false;
        }
    }

    public String toString() {
        Object objA;
        StringBuilder sb = new StringBuilder();
        sb.append("Connection{");
        sb.append(this.f945s.a().l().h());
        sb.append(':');
        sb.append(this.f945s.a().l().l());
        sb.append(',');
        sb.append(" proxy=");
        sb.append(this.f945s.b());
        sb.append(" hostAddress=");
        sb.append(this.f945s.d());
        sb.append(" cipherSuite=");
        s sVar = this.f931e;
        if (sVar == null || (objA = sVar.a()) == null) {
            objA = "none";
        }
        sb.append(objA);
        sb.append(" protocol=");
        sb.append(this.f932f);
        sb.append('}');
        return sb.toString();
    }

    public final boolean u(boolean z3) {
        long j3;
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
        long jNanoTime = System.nanoTime();
        Socket socket = this.f929c;
        t2.j.c(socket);
        Socket socket2 = this.f930d;
        t2.j.c(socket2);
        Q2.k kVar = this.f934h;
        t2.j.c(kVar);
        if (socket.isClosed() || socket2.isClosed() || socket2.isInputShutdown() || socket2.isOutputShutdown()) {
            return false;
        }
        J2.f fVar = this.f933g;
        if (fVar != null) {
            return fVar.I0(jNanoTime);
        }
        synchronized (this) {
            j3 = jNanoTime - this.f943q;
        }
        if (j3 < 10000000000L || !z3) {
            return true;
        }
        return C2.c.D(socket2, kVar);
    }

    public final boolean v() {
        return this.f933g != null;
    }

    public final H2.d w(z zVar, H2.g gVar) throws SocketException {
        t2.j.f(zVar, "client");
        t2.j.f(gVar, "chain");
        Socket socket = this.f930d;
        t2.j.c(socket);
        Q2.k kVar = this.f934h;
        t2.j.c(kVar);
        Q2.j jVar = this.f935i;
        t2.j.c(jVar);
        J2.f fVar = this.f933g;
        if (fVar != null) {
            return new J2.g(zVar, this, gVar, fVar);
        }
        socket.setSoTimeout(gVar.k());
        G gF = kVar.f();
        long jG = gVar.g();
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        gF.g(jG, timeUnit);
        jVar.f().g(gVar.j(), timeUnit);
        return new I2.b(zVar, this, kVar, jVar);
    }

    public final d.AbstractC0035d x(G2.c cVar) throws SocketException {
        t2.j.f(cVar, "exchange");
        Socket socket = this.f930d;
        t2.j.c(socket);
        Q2.k kVar = this.f934h;
        t2.j.c(kVar);
        Q2.j jVar = this.f935i;
        t2.j.c(jVar);
        socket.setSoTimeout(0);
        z();
        return new d(cVar, kVar, jVar, true, kVar, jVar);
    }

    public final synchronized void y() {
        this.f937k = true;
    }

    public final synchronized void z() {
        this.f936j = true;
    }
}
