package P2;

import B2.A;
import B2.B;
import B2.D;
import B2.H;
import B2.I;
import B2.InterfaceC0167e;
import B2.InterfaceC0168f;
import B2.z;
import P2.g;
import Q2.k;
import Q2.l;
import i2.AbstractC0586n;
import java.io.Closeable;
import java.io.IOException;
import java.net.ProtocolException;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import t2.r;
import t2.t;

/* JADX INFO: loaded from: classes.dex */
public final class d implements H, g.a {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    public static final b f2222A = new b(null);

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private static final List f2223z = AbstractC0586n.b(A.HTTP_1_1);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final String f2224a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private InterfaceC0167e f2225b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private F2.a f2226c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private P2.g f2227d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private P2.h f2228e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private F2.d f2229f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private String f2230g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private AbstractC0035d f2231h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final ArrayDeque f2232i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final ArrayDeque f2233j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private long f2234k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f2235l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f2236m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private String f2237n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f2238o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f2239p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private int f2240q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f2241r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f2242s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final B f2243t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final I f2244u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final Random f2245v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private final long f2246w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private P2.e f2247x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private long f2248y;

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f2249a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final l f2250b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final long f2251c;

        public a(int i3, l lVar, long j3) {
            this.f2249a = i3;
            this.f2250b = lVar;
            this.f2251c = j3;
        }

        public final long a() {
            return this.f2251c;
        }

        public final int b() {
            return this.f2249a;
        }

        public final l c() {
            return this.f2250b;
        }
    }

    public static final class b {
        private b() {
        }

        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public static final class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f2252a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final l f2253b;

        public c(int i3, l lVar) {
            j.f(lVar, "data");
            this.f2252a = i3;
            this.f2253b = lVar;
        }

        public final l a() {
            return this.f2253b;
        }

        public final int b() {
            return this.f2252a;
        }
    }

    /* JADX INFO: renamed from: P2.d$d, reason: collision with other inner class name */
    public static abstract class AbstractC0035d implements Closeable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final boolean f2254b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final k f2255c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final Q2.j f2256d;

        public AbstractC0035d(boolean z3, k kVar, Q2.j jVar) {
            j.f(kVar, "source");
            j.f(jVar, "sink");
            this.f2254b = z3;
            this.f2255c = kVar;
            this.f2256d = jVar;
        }

        public final boolean b() {
            return this.f2254b;
        }

        public final Q2.j i() {
            return this.f2256d;
        }

        public final k p() {
            return this.f2255c;
        }
    }

    private final class e extends F2.a {
        public e() {
            super(d.this.f2230g + " writer", false, 2, null);
        }

        @Override // F2.a
        public long f() {
            try {
                return d.this.x() ? 0L : -1L;
            } catch (IOException e3) {
                d.this.q(e3, null);
                return -1L;
            }
        }
    }

    public static final class f implements InterfaceC0168f {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ B f2259b;

        f(B b3) {
            this.f2259b = b3;
        }

        @Override // B2.InterfaceC0168f
        public void a(InterfaceC0167e interfaceC0167e, D d3) {
            j.f(interfaceC0167e, "call");
            j.f(d3, "response");
            G2.c cVarD = d3.D();
            try {
                d.this.n(d3, cVarD);
                j.c(cVarD);
                AbstractC0035d abstractC0035dM = cVarD.m();
                P2.e eVarA = P2.e.f2277g.a(d3.e0());
                d.this.f2247x = eVarA;
                if (!d.this.t(eVarA)) {
                    synchronized (d.this) {
                        d.this.f2233j.clear();
                        d.this.b(1010, "unexpected Sec-WebSocket-Extensions in response header");
                    }
                }
                try {
                    d.this.s(C2.c.f586i + " WebSocket " + this.f2259b.l().n(), abstractC0035dM);
                    d.this.r().f(d.this, d3);
                    d.this.u();
                } catch (Exception e3) {
                    d.this.q(e3, null);
                }
            } catch (IOException e4) {
                if (cVarD != null) {
                    cVarD.u();
                }
                d.this.q(e4, d3);
                C2.c.j(d3);
            }
        }

        @Override // B2.InterfaceC0168f
        public void b(InterfaceC0167e interfaceC0167e, IOException iOException) {
            j.f(interfaceC0167e, "call");
            j.f(iOException, "e");
            d.this.q(iOException, null);
        }
    }

    public static final class g extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f2260e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ long f2261f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ d f2262g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ String f2263h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ AbstractC0035d f2264i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        final /* synthetic */ P2.e f2265j;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public g(String str, String str2, long j3, d dVar, String str3, AbstractC0035d abstractC0035d, P2.e eVar) {
            super(str2, false, 2, null);
            this.f2260e = str;
            this.f2261f = j3;
            this.f2262g = dVar;
            this.f2263h = str3;
            this.f2264i = abstractC0035d;
            this.f2265j = eVar;
        }

        @Override // F2.a
        public long f() {
            this.f2262g.y();
            return this.f2261f;
        }
    }

    public static final class h extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f2266e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ boolean f2267f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ d f2268g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ P2.h f2269h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ l f2270i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        final /* synthetic */ t f2271j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        final /* synthetic */ r f2272k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        final /* synthetic */ t f2273l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        final /* synthetic */ t f2274m;

        /* JADX INFO: renamed from: n, reason: collision with root package name */
        final /* synthetic */ t f2275n;

        /* JADX INFO: renamed from: o, reason: collision with root package name */
        final /* synthetic */ t f2276o;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public h(String str, boolean z3, String str2, boolean z4, d dVar, P2.h hVar, l lVar, t tVar, r rVar, t tVar2, t tVar3, t tVar4, t tVar5) {
            super(str2, z4);
            this.f2266e = str;
            this.f2267f = z3;
            this.f2268g = dVar;
            this.f2269h = hVar;
            this.f2270i = lVar;
            this.f2271j = tVar;
            this.f2272k = rVar;
            this.f2273l = tVar2;
            this.f2274m = tVar3;
            this.f2275n = tVar4;
            this.f2276o = tVar5;
        }

        @Override // F2.a
        public long f() {
            this.f2268g.m();
            return -1L;
        }
    }

    public d(F2.e eVar, B b3, I i3, Random random, long j3, P2.e eVar2, long j4) {
        j.f(eVar, "taskRunner");
        j.f(b3, "originalRequest");
        j.f(i3, "listener");
        j.f(random, "random");
        this.f2243t = b3;
        this.f2244u = i3;
        this.f2245v = random;
        this.f2246w = j3;
        this.f2247x = eVar2;
        this.f2248y = j4;
        this.f2229f = eVar.i();
        this.f2232i = new ArrayDeque();
        this.f2233j = new ArrayDeque();
        this.f2236m = -1;
        if (!j.b("GET", b3.h())) {
            throw new IllegalArgumentException(("Request must be GET: " + b3.h()).toString());
        }
        l.a aVar = l.f2556f;
        byte[] bArr = new byte[16];
        random.nextBytes(bArr);
        h2.r rVar = h2.r.f9288a;
        this.f2224a = l.a.h(aVar, bArr, 0, 0, 3, null).a();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean t(P2.e eVar) {
        if (eVar.f2283f || eVar.f2279b != null) {
            return false;
        }
        Integer num = eVar.f2281d;
        if (num == null) {
            return true;
        }
        int iIntValue = num.intValue();
        return 8 <= iIntValue && 15 >= iIntValue;
    }

    private final void v() {
        if (!C2.c.f585h || Thread.holdsLock(this)) {
            F2.a aVar = this.f2226c;
            if (aVar != null) {
                F2.d.j(this.f2229f, aVar, 0L, 2, null);
                return;
            }
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Thread ");
        Thread threadCurrentThread = Thread.currentThread();
        j.e(threadCurrentThread, "Thread.currentThread()");
        sb.append(threadCurrentThread.getName());
        sb.append(" MUST hold lock on ");
        sb.append(this);
        throw new AssertionError(sb.toString());
    }

    private final synchronized boolean w(l lVar, int i3) {
        if (!this.f2238o && !this.f2235l) {
            if (this.f2234k + ((long) lVar.v()) > 16777216) {
                b(1001, null);
                return false;
            }
            this.f2234k += (long) lVar.v();
            this.f2233j.add(new c(i3, lVar));
            v();
            return true;
        }
        return false;
    }

    @Override // P2.g.a
    public synchronized void a(l lVar) {
        j.f(lVar, "payload");
        this.f2241r++;
        this.f2242s = false;
    }

    @Override // B2.H
    public boolean b(int i3, String str) {
        return o(i3, str, 60000L);
    }

    @Override // B2.H
    public boolean c(String str) {
        j.f(str, "text");
        return w(l.f2556f.e(str), 1);
    }

    @Override // P2.g.a
    public synchronized void d(l lVar) {
        try {
            j.f(lVar, "payload");
            if (!this.f2238o && (!this.f2235l || !this.f2233j.isEmpty())) {
                this.f2232i.add(lVar);
                v();
                this.f2240q++;
            }
        } finally {
        }
    }

    @Override // B2.H
    public boolean e(l lVar) {
        j.f(lVar, "bytes");
        return w(lVar, 2);
    }

    @Override // P2.g.a
    public void f(l lVar) {
        j.f(lVar, "bytes");
        this.f2244u.d(this, lVar);
    }

    @Override // P2.g.a
    public void g(String str) {
        j.f(str, "text");
        this.f2244u.e(this, str);
    }

    @Override // P2.g.a
    public void h(int i3, String str) {
        AbstractC0035d abstractC0035d;
        P2.g gVar;
        P2.h hVar;
        j.f(str, "reason");
        if (!(i3 != -1)) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        synchronized (this) {
            try {
                if (!(this.f2236m == -1)) {
                    throw new IllegalStateException("already closed");
                }
                this.f2236m = i3;
                this.f2237n = str;
                abstractC0035d = null;
                if (this.f2235l && this.f2233j.isEmpty()) {
                    AbstractC0035d abstractC0035d2 = this.f2231h;
                    this.f2231h = null;
                    gVar = this.f2227d;
                    this.f2227d = null;
                    hVar = this.f2228e;
                    this.f2228e = null;
                    this.f2229f.n();
                    abstractC0035d = abstractC0035d2;
                } else {
                    gVar = null;
                    hVar = null;
                }
                h2.r rVar = h2.r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
        try {
            this.f2244u.b(this, i3, str);
            if (abstractC0035d != null) {
                this.f2244u.a(this, i3, str);
            }
        } finally {
            if (abstractC0035d != null) {
                C2.c.j(abstractC0035d);
            }
            if (gVar != null) {
                C2.c.j(gVar);
            }
            if (hVar != null) {
                C2.c.j(hVar);
            }
        }
    }

    public void m() {
        InterfaceC0167e interfaceC0167e = this.f2225b;
        j.c(interfaceC0167e);
        interfaceC0167e.cancel();
    }

    public final void n(D d3, G2.c cVar) throws ProtocolException {
        j.f(d3, "response");
        if (d3.A() != 101) {
            throw new ProtocolException("Expected HTTP 101 response but was '" + d3.A() + ' ' + d3.n0() + '\'');
        }
        String strD0 = D.d0(d3, "Connection", null, 2, null);
        if (!z2.g.j("Upgrade", strD0, true)) {
            throw new ProtocolException("Expected 'Connection' header value 'Upgrade' but was '" + strD0 + '\'');
        }
        String strD02 = D.d0(d3, "Upgrade", null, 2, null);
        if (!z2.g.j("websocket", strD02, true)) {
            throw new ProtocolException("Expected 'Upgrade' header value 'websocket' but was '" + strD02 + '\'');
        }
        String strD03 = D.d0(d3, "Sec-WebSocket-Accept", null, 2, null);
        String strA = l.f2556f.e(this.f2224a + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").t().a();
        if (j.b(strA, strD03)) {
            if (cVar == null) {
                throw new ProtocolException("Web Socket exchange missing: bad interceptor?");
            }
            return;
        }
        throw new ProtocolException("Expected 'Sec-WebSocket-Accept' header value '" + strA + "' but was '" + strD03 + '\'');
    }

    public final synchronized boolean o(int i3, String str, long j3) {
        l lVarE;
        try {
            P2.f.f2284a.c(i3);
            if (str != null) {
                lVarE = l.f2556f.e(str);
                if (!(((long) lVarE.v()) <= 123)) {
                    throw new IllegalArgumentException(("reason.size() > 123: " + str).toString());
                }
            } else {
                lVarE = null;
            }
            if (!this.f2238o && !this.f2235l) {
                this.f2235l = true;
                this.f2233j.add(new a(i3, lVarE, j3));
                v();
                return true;
            }
            return false;
        } finally {
        }
    }

    public final void p(z zVar) {
        j.f(zVar, "client");
        if (this.f2243t.d("Sec-WebSocket-Extensions") != null) {
            q(new ProtocolException("Request header not permitted: 'Sec-WebSocket-Extensions'"), null);
            return;
        }
        z zVarC = zVar.C().i(B2.r.f400a).Q(f2223z).c();
        B b3 = this.f2243t.i().e("Upgrade", "websocket").e("Connection", "Upgrade").e("Sec-WebSocket-Key", this.f2224a).e("Sec-WebSocket-Version", "13").e("Sec-WebSocket-Extensions", "permessage-deflate").b();
        G2.e eVar = new G2.e(zVarC, b3, true);
        this.f2225b = eVar;
        j.c(eVar);
        eVar.p(new f(b3));
    }

    public final void q(Exception exc, D d3) {
        j.f(exc, "e");
        synchronized (this) {
            if (this.f2238o) {
                return;
            }
            this.f2238o = true;
            AbstractC0035d abstractC0035d = this.f2231h;
            this.f2231h = null;
            P2.g gVar = this.f2227d;
            this.f2227d = null;
            P2.h hVar = this.f2228e;
            this.f2228e = null;
            this.f2229f.n();
            h2.r rVar = h2.r.f9288a;
            try {
                this.f2244u.c(this, exc, d3);
            } finally {
                if (abstractC0035d != null) {
                    C2.c.j(abstractC0035d);
                }
                if (gVar != null) {
                    C2.c.j(gVar);
                }
                if (hVar != null) {
                    C2.c.j(hVar);
                }
            }
        }
    }

    public final I r() {
        return this.f2244u;
    }

    public final void s(String str, AbstractC0035d abstractC0035d) {
        j.f(str, "name");
        j.f(abstractC0035d, "streams");
        P2.e eVar = this.f2247x;
        j.c(eVar);
        synchronized (this) {
            try {
                this.f2230g = str;
                this.f2231h = abstractC0035d;
                this.f2228e = new P2.h(abstractC0035d.b(), abstractC0035d.i(), this.f2245v, eVar.f2278a, eVar.a(abstractC0035d.b()), this.f2248y);
                this.f2226c = new e();
                long j3 = this.f2246w;
                if (j3 != 0) {
                    long nanos = TimeUnit.MILLISECONDS.toNanos(j3);
                    String str2 = str + " ping";
                    this.f2229f.i(new g(str2, str2, nanos, this, str, abstractC0035d, eVar), nanos);
                }
                if (!this.f2233j.isEmpty()) {
                    v();
                }
                h2.r rVar = h2.r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
        this.f2227d = new P2.g(abstractC0035d.b(), abstractC0035d.p(), this, eVar.f2278a, eVar.a(!abstractC0035d.b()));
    }

    public final void u() {
        while (this.f2236m == -1) {
            P2.g gVar = this.f2227d;
            j.c(gVar);
            gVar.b();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0186  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0191  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x019c  */
    /* JADX WARN: Removed duplicated region for block: B:96:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r1v2 */
    /* JADX WARN: Type inference failed for: r1v29 */
    /* JADX WARN: Type inference failed for: r1v3, types: [t2.t] */
    /* JADX WARN: Type inference failed for: r1v30 */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v18 */
    /* JADX WARN: Type inference failed for: r2v2, types: [t2.t] */
    /* JADX WARN: Type inference failed for: r2v8 */
    /* JADX WARN: Type inference failed for: r3v23 */
    /* JADX WARN: Type inference failed for: r3v24 */
    /* JADX WARN: Type inference failed for: r3v25 */
    /* JADX WARN: Type inference failed for: r3v26 */
    /* JADX WARN: Type inference failed for: r3v27 */
    /* JADX WARN: Type inference failed for: r3v28 */
    /* JADX WARN: Type inference failed for: r3v3 */
    /* JADX WARN: Type inference failed for: r3v4 */
    /* JADX WARN: Type inference failed for: r3v5 */
    /* JADX WARN: Type inference failed for: r3v6, types: [t2.t] */
    /* JADX WARN: Type inference failed for: r3v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean x() throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 475
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: P2.d.x():boolean");
    }

    public final void y() {
        synchronized (this) {
            try {
                if (this.f2238o) {
                    return;
                }
                P2.h hVar = this.f2228e;
                if (hVar != null) {
                    int i3 = this.f2242s ? this.f2239p : -1;
                    this.f2239p++;
                    this.f2242s = true;
                    h2.r rVar = h2.r.f9288a;
                    if (i3 == -1) {
                        try {
                            hVar.r(l.f2555e);
                            return;
                        } catch (IOException e3) {
                            q(e3, null);
                            return;
                        }
                    }
                    q(new SocketTimeoutException("sent ping but didn't receive pong within " + this.f2246w + "ms (after " + (i3 - 1) + " successful ping/pongs)"), null);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
