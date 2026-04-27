package J2;

import J2.h;
import h2.r;
import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;
import t2.s;
import t2.t;

/* JADX INFO: loaded from: classes.dex */
public final class f implements Closeable {

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private static final m f1511D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    public static final c f1512E = new c(null);

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private final J2.j f1513A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final e f1514B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final Set f1515C;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f1516b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d f1517c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Map f1518d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final String f1519e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f1520f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f1521g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f1522h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final F2.e f1523i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final F2.d f1524j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final F2.d f1525k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final F2.d f1526l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final J2.l f1527m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private long f1528n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private long f1529o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private long f1530p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private long f1531q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private long f1532r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private long f1533s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final m f1534t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private m f1535u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private long f1536v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private long f1537w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private long f1538x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private long f1539y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private final Socket f1540z;

    public static final class a extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f1541e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ f f1542f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ long f1543g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(String str, String str2, f fVar, long j3) {
            super(str2, false, 2, null);
            this.f1541e = str;
            this.f1542f = fVar;
            this.f1543g = j3;
        }

        @Override // F2.a
        public long f() {
            boolean z3;
            synchronized (this.f1542f) {
                if (this.f1542f.f1529o < this.f1542f.f1528n) {
                    z3 = true;
                } else {
                    this.f1542f.f1528n++;
                    z3 = false;
                }
            }
            if (z3) {
                this.f1542f.w0(null);
                return -1L;
            }
            this.f1542f.a1(false, 1, 0);
            return this.f1543g;
        }
    }

    public static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public Socket f1544a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public String f1545b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public Q2.k f1546c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public Q2.j f1547d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private d f1548e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private J2.l f1549f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private int f1550g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private boolean f1551h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final F2.e f1552i;

        public b(boolean z3, F2.e eVar) {
            t2.j.f(eVar, "taskRunner");
            this.f1551h = z3;
            this.f1552i = eVar;
            this.f1548e = d.f1553a;
            this.f1549f = J2.l.f1683a;
        }

        public final f a() {
            return new f(this);
        }

        public final boolean b() {
            return this.f1551h;
        }

        public final String c() {
            String str = this.f1545b;
            if (str == null) {
                t2.j.s("connectionName");
            }
            return str;
        }

        public final d d() {
            return this.f1548e;
        }

        public final int e() {
            return this.f1550g;
        }

        public final J2.l f() {
            return this.f1549f;
        }

        public final Q2.j g() {
            Q2.j jVar = this.f1547d;
            if (jVar == null) {
                t2.j.s("sink");
            }
            return jVar;
        }

        public final Socket h() {
            Socket socket = this.f1544a;
            if (socket == null) {
                t2.j.s("socket");
            }
            return socket;
        }

        public final Q2.k i() {
            Q2.k kVar = this.f1546c;
            if (kVar == null) {
                t2.j.s("source");
            }
            return kVar;
        }

        public final F2.e j() {
            return this.f1552i;
        }

        public final b k(d dVar) {
            t2.j.f(dVar, "listener");
            this.f1548e = dVar;
            return this;
        }

        public final b l(int i3) {
            this.f1550g = i3;
            return this;
        }

        public final b m(Socket socket, String str, Q2.k kVar, Q2.j jVar) {
            String str2;
            t2.j.f(socket, "socket");
            t2.j.f(str, "peerName");
            t2.j.f(kVar, "source");
            t2.j.f(jVar, "sink");
            this.f1544a = socket;
            if (this.f1551h) {
                str2 = C2.c.f586i + ' ' + str;
            } else {
                str2 = "MockWebServer " + str;
            }
            this.f1545b = str2;
            this.f1546c = kVar;
            this.f1547d = jVar;
            return this;
        }
    }

    public static final class c {
        private c() {
        }

        public final m a() {
            return f.f1511D;
        }

        public /* synthetic */ c(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public static abstract class d {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final b f1554b = new b(null);

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final d f1553a = new a();

        public static final class a extends d {
            a() {
            }

            @Override // J2.f.d
            public void b(J2.i iVar) {
                t2.j.f(iVar, "stream");
                iVar.d(J2.b.REFUSED_STREAM, null);
            }
        }

        public static final class b {
            private b() {
            }

            public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }
        }

        public void a(f fVar, m mVar) {
            t2.j.f(fVar, "connection");
            t2.j.f(mVar, "settings");
        }

        public abstract void b(J2.i iVar);
    }

    /* JADX INFO: renamed from: J2.f$f, reason: collision with other inner class name */
    public static final class C0023f extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f1583e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ boolean f1584f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ f f1585g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ int f1586h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ Q2.i f1587i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        final /* synthetic */ int f1588j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        final /* synthetic */ boolean f1589k;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C0023f(String str, boolean z3, String str2, boolean z4, f fVar, int i3, Q2.i iVar, int i4, boolean z5) {
            super(str2, z4);
            this.f1583e = str;
            this.f1584f = z3;
            this.f1585g = fVar;
            this.f1586h = i3;
            this.f1587i = iVar;
            this.f1588j = i4;
            this.f1589k = z5;
        }

        @Override // F2.a
        public long f() {
            try {
                boolean zC = this.f1585g.f1527m.c(this.f1586h, this.f1587i, this.f1588j, this.f1589k);
                if (zC) {
                    this.f1585g.H0().W(this.f1586h, J2.b.CANCEL);
                }
                if (!zC && !this.f1589k) {
                    return -1L;
                }
                synchronized (this.f1585g) {
                    this.f1585g.f1515C.remove(Integer.valueOf(this.f1586h));
                }
                return -1L;
            } catch (IOException unused) {
                return -1L;
            }
        }
    }

    public static final class g extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f1590e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ boolean f1591f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ f f1592g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ int f1593h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ List f1594i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        final /* synthetic */ boolean f1595j;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public g(String str, boolean z3, String str2, boolean z4, f fVar, int i3, List list, boolean z5) {
            super(str2, z4);
            this.f1590e = str;
            this.f1591f = z3;
            this.f1592g = fVar;
            this.f1593h = i3;
            this.f1594i = list;
            this.f1595j = z5;
        }

        @Override // F2.a
        public long f() {
            boolean zB = this.f1592g.f1527m.b(this.f1593h, this.f1594i, this.f1595j);
            if (zB) {
                try {
                    this.f1592g.H0().W(this.f1593h, J2.b.CANCEL);
                } catch (IOException unused) {
                    return -1L;
                }
            }
            if (!zB && !this.f1595j) {
                return -1L;
            }
            synchronized (this.f1592g) {
                this.f1592g.f1515C.remove(Integer.valueOf(this.f1593h));
            }
            return -1L;
        }
    }

    public static final class h extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f1596e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ boolean f1597f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ f f1598g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ int f1599h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ List f1600i;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public h(String str, boolean z3, String str2, boolean z4, f fVar, int i3, List list) {
            super(str2, z4);
            this.f1596e = str;
            this.f1597f = z3;
            this.f1598g = fVar;
            this.f1599h = i3;
            this.f1600i = list;
        }

        @Override // F2.a
        public long f() {
            if (!this.f1598g.f1527m.a(this.f1599h, this.f1600i)) {
                return -1L;
            }
            try {
                this.f1598g.H0().W(this.f1599h, J2.b.CANCEL);
                synchronized (this.f1598g) {
                    this.f1598g.f1515C.remove(Integer.valueOf(this.f1599h));
                }
                return -1L;
            } catch (IOException unused) {
                return -1L;
            }
        }
    }

    public static final class i extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f1601e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ boolean f1602f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ f f1603g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ int f1604h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ J2.b f1605i;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public i(String str, boolean z3, String str2, boolean z4, f fVar, int i3, J2.b bVar) {
            super(str2, z4);
            this.f1601e = str;
            this.f1602f = z3;
            this.f1603g = fVar;
            this.f1604h = i3;
            this.f1605i = bVar;
        }

        @Override // F2.a
        public long f() {
            this.f1603g.f1527m.d(this.f1604h, this.f1605i);
            synchronized (this.f1603g) {
                this.f1603g.f1515C.remove(Integer.valueOf(this.f1604h));
                r rVar = r.f9288a;
            }
            return -1L;
        }
    }

    public static final class j extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f1606e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ boolean f1607f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ f f1608g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public j(String str, boolean z3, String str2, boolean z4, f fVar) {
            super(str2, z4);
            this.f1606e = str;
            this.f1607f = z3;
            this.f1608g = fVar;
        }

        @Override // F2.a
        public long f() {
            this.f1608g.a1(false, 2, 0);
            return -1L;
        }
    }

    public static final class k extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f1609e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ boolean f1610f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ f f1611g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ int f1612h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ J2.b f1613i;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public k(String str, boolean z3, String str2, boolean z4, f fVar, int i3, J2.b bVar) {
            super(str2, z4);
            this.f1609e = str;
            this.f1610f = z3;
            this.f1611g = fVar;
            this.f1612h = i3;
            this.f1613i = bVar;
        }

        @Override // F2.a
        public long f() {
            try {
                this.f1611g.b1(this.f1612h, this.f1613i);
                return -1L;
            } catch (IOException e3) {
                this.f1611g.w0(e3);
                return -1L;
            }
        }
    }

    public static final class l extends F2.a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ String f1614e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ boolean f1615f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ f f1616g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ int f1617h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ long f1618i;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public l(String str, boolean z3, String str2, boolean z4, f fVar, int i3, long j3) {
            super(str2, z4);
            this.f1614e = str;
            this.f1615f = z3;
            this.f1616g = fVar;
            this.f1617h = i3;
            this.f1618i = j3;
        }

        @Override // F2.a
        public long f() {
            try {
                this.f1616g.H0().d0(this.f1617h, this.f1618i);
                return -1L;
            } catch (IOException e3) {
                this.f1616g.w0(e3);
                return -1L;
            }
        }
    }

    static {
        m mVar = new m();
        mVar.h(7, 65535);
        mVar.h(5, 16384);
        f1511D = mVar;
    }

    public f(b bVar) {
        t2.j.f(bVar, "builder");
        boolean zB = bVar.b();
        this.f1516b = zB;
        this.f1517c = bVar.d();
        this.f1518d = new LinkedHashMap();
        String strC = bVar.c();
        this.f1519e = strC;
        this.f1521g = bVar.b() ? 3 : 2;
        F2.e eVarJ = bVar.j();
        this.f1523i = eVarJ;
        F2.d dVarI = eVarJ.i();
        this.f1524j = dVarI;
        this.f1525k = eVarJ.i();
        this.f1526l = eVarJ.i();
        this.f1527m = bVar.f();
        m mVar = new m();
        if (bVar.b()) {
            mVar.h(7, 16777216);
        }
        r rVar = r.f9288a;
        this.f1534t = mVar;
        this.f1535u = f1511D;
        this.f1539y = r2.c();
        this.f1540z = bVar.h();
        this.f1513A = new J2.j(bVar.g(), zB);
        this.f1514B = new e(this, new J2.h(bVar.i(), zB));
        this.f1515C = new LinkedHashSet();
        if (bVar.e() != 0) {
            long nanos = TimeUnit.MILLISECONDS.toNanos(bVar.e());
            String str = strC + " ping";
            dVarI.i(new a(str, str, this, nanos), nanos);
        }
    }

    private final J2.i J0(int i3, List list, boolean z3) {
        int i4;
        J2.i iVar;
        boolean z4 = true;
        boolean z5 = !z3;
        synchronized (this.f1513A) {
            try {
                synchronized (this) {
                    try {
                        if (this.f1521g > 1073741823) {
                            U0(J2.b.REFUSED_STREAM);
                        }
                        if (this.f1522h) {
                            throw new J2.a();
                        }
                        i4 = this.f1521g;
                        this.f1521g = i4 + 2;
                        iVar = new J2.i(i4, this, z5, false, null);
                        if (z3 && this.f1538x < this.f1539y && iVar.r() < iVar.q()) {
                            z4 = false;
                        }
                        if (iVar.u()) {
                            this.f1518d.put(Integer.valueOf(i4), iVar);
                        }
                        r rVar = r.f9288a;
                    } finally {
                    }
                }
                if (i3 == 0) {
                    this.f1513A.y(z5, i4, list);
                } else {
                    if (this.f1516b) {
                        throw new IllegalArgumentException("client streams shouldn't have associated stream IDs");
                    }
                    this.f1513A.P(i3, i4, list);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (z4) {
            this.f1513A.flush();
        }
        return iVar;
    }

    public static /* synthetic */ void W0(f fVar, boolean z3, F2.e eVar, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            z3 = true;
        }
        if ((i3 & 2) != 0) {
            eVar = F2.e.f751h;
        }
        fVar.V0(z3, eVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void w0(IOException iOException) {
        J2.b bVar = J2.b.PROTOCOL_ERROR;
        v0(bVar, bVar, iOException);
    }

    public final d A0() {
        return this.f1517c;
    }

    public final int B0() {
        return this.f1521g;
    }

    public final m C0() {
        return this.f1534t;
    }

    public final m D0() {
        return this.f1535u;
    }

    public final synchronized J2.i E0(int i3) {
        return (J2.i) this.f1518d.get(Integer.valueOf(i3));
    }

    public final Map F0() {
        return this.f1518d;
    }

    public final long G0() {
        return this.f1539y;
    }

    public final J2.j H0() {
        return this.f1513A;
    }

    public final synchronized boolean I0(long j3) {
        if (this.f1522h) {
            return false;
        }
        if (this.f1531q < this.f1530p) {
            if (j3 >= this.f1533s) {
                return false;
            }
        }
        return true;
    }

    public final J2.i K0(List list, boolean z3) {
        t2.j.f(list, "requestHeaders");
        return J0(0, list, z3);
    }

    public final void L0(int i3, Q2.k kVar, int i4, boolean z3) {
        t2.j.f(kVar, "source");
        Q2.i iVar = new Q2.i();
        long j3 = i4;
        kVar.i0(j3);
        kVar.R(iVar, j3);
        F2.d dVar = this.f1525k;
        String str = this.f1519e + '[' + i3 + "] onData";
        dVar.i(new C0023f(str, true, str, true, this, i3, iVar, i4, z3), 0L);
    }

    public final void M0(int i3, List list, boolean z3) {
        t2.j.f(list, "requestHeaders");
        F2.d dVar = this.f1525k;
        String str = this.f1519e + '[' + i3 + "] onHeaders";
        dVar.i(new g(str, true, str, true, this, i3, list, z3), 0L);
    }

    public final void N0(int i3, List list) {
        t2.j.f(list, "requestHeaders");
        synchronized (this) {
            if (this.f1515C.contains(Integer.valueOf(i3))) {
                c1(i3, J2.b.PROTOCOL_ERROR);
                return;
            }
            this.f1515C.add(Integer.valueOf(i3));
            F2.d dVar = this.f1525k;
            String str = this.f1519e + '[' + i3 + "] onRequest";
            dVar.i(new h(str, true, str, true, this, i3, list), 0L);
        }
    }

    public final void O0(int i3, J2.b bVar) {
        t2.j.f(bVar, "errorCode");
        F2.d dVar = this.f1525k;
        String str = this.f1519e + '[' + i3 + "] onReset";
        dVar.i(new i(str, true, str, true, this, i3, bVar), 0L);
    }

    public final boolean P0(int i3) {
        return i3 != 0 && (i3 & 1) == 0;
    }

    public final synchronized J2.i Q0(int i3) {
        J2.i iVar;
        iVar = (J2.i) this.f1518d.remove(Integer.valueOf(i3));
        notifyAll();
        return iVar;
    }

    public final void R0() {
        synchronized (this) {
            long j3 = this.f1531q;
            long j4 = this.f1530p;
            if (j3 < j4) {
                return;
            }
            this.f1530p = j4 + 1;
            this.f1533s = System.nanoTime() + ((long) 1000000000);
            r rVar = r.f9288a;
            F2.d dVar = this.f1524j;
            String str = this.f1519e + " ping";
            dVar.i(new j(str, true, str, true, this), 0L);
        }
    }

    public final void S0(int i3) {
        this.f1520f = i3;
    }

    public final void T0(m mVar) {
        t2.j.f(mVar, "<set-?>");
        this.f1535u = mVar;
    }

    public final void U0(J2.b bVar) {
        t2.j.f(bVar, "statusCode");
        synchronized (this.f1513A) {
            synchronized (this) {
                if (this.f1522h) {
                    return;
                }
                this.f1522h = true;
                int i3 = this.f1520f;
                r rVar = r.f9288a;
                this.f1513A.x(i3, bVar, C2.c.f578a);
            }
        }
    }

    public final void V0(boolean z3, F2.e eVar) {
        t2.j.f(eVar, "taskRunner");
        if (z3) {
            this.f1513A.i();
            this.f1513A.Z(this.f1534t);
            if (this.f1534t.c() != 65535) {
                this.f1513A.d0(0, r7 - 65535);
            }
        }
        F2.d dVarI = eVar.i();
        String str = this.f1519e;
        dVarI.i(new F2.c(this.f1514B, str, true, str, true), 0L);
    }

    public final synchronized void X0(long j3) {
        long j4 = this.f1536v + j3;
        this.f1536v = j4;
        long j5 = j4 - this.f1537w;
        if (j5 >= this.f1534t.c() / 2) {
            d1(0, j5);
            this.f1537w += j5;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0035, code lost:
    
        r2 = java.lang.Math.min((int) java.lang.Math.min(r12, r6 - r4), r8.f1513A.A());
        r6 = r2;
        r8.f1538x += r6;
        r4 = h2.r.f9288a;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void Y0(int r9, boolean r10, Q2.i r11, long r12) {
        /*
            r8 = this;
            r0 = 0
            int r2 = (r12 > r0 ? 1 : (r12 == r0 ? 0 : -1))
            r3 = 0
            if (r2 != 0) goto Ld
            J2.j r12 = r8.f1513A
            r12.p(r10, r9, r11, r3)
            return
        Ld:
            int r2 = (r12 > r0 ? 1 : (r12 == r0 ? 0 : -1))
            if (r2 <= 0) goto L6c
            monitor-enter(r8)
        L12:
            long r4 = r8.f1538x     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5d
            long r6 = r8.f1539y     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5d
            int r2 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r2 < 0) goto L34
            java.util.Map r2 = r8.f1518d     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5d
            java.lang.Integer r4 = java.lang.Integer.valueOf(r9)     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5d
            boolean r2 = r2.containsKey(r4)     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5d
            if (r2 == 0) goto L2c
            r8.wait()     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5d
            goto L12
        L2a:
            r9 = move-exception
            goto L6a
        L2c:
            java.io.IOException r9 = new java.io.IOException     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5d
            java.lang.String r10 = "stream closed"
            r9.<init>(r10)     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5d
            throw r9     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5d
        L34:
            long r6 = r6 - r4
            long r4 = java.lang.Math.min(r12, r6)     // Catch: java.lang.Throwable -> L2a
            int r2 = (int) r4     // Catch: java.lang.Throwable -> L2a
            J2.j r4 = r8.f1513A     // Catch: java.lang.Throwable -> L2a
            int r4 = r4.A()     // Catch: java.lang.Throwable -> L2a
            int r2 = java.lang.Math.min(r2, r4)     // Catch: java.lang.Throwable -> L2a
            long r4 = r8.f1538x     // Catch: java.lang.Throwable -> L2a
            long r6 = (long) r2     // Catch: java.lang.Throwable -> L2a
            long r4 = r4 + r6
            r8.f1538x = r4     // Catch: java.lang.Throwable -> L2a
            h2.r r4 = h2.r.f9288a     // Catch: java.lang.Throwable -> L2a
            monitor-exit(r8)
            long r12 = r12 - r6
            J2.j r4 = r8.f1513A
            if (r10 == 0) goto L58
            int r5 = (r12 > r0 ? 1 : (r12 == r0 ? 0 : -1))
            if (r5 != 0) goto L58
            r5 = 1
            goto L59
        L58:
            r5 = r3
        L59:
            r4.p(r5, r9, r11, r2)
            goto Ld
        L5d:
            java.lang.Thread r9 = java.lang.Thread.currentThread()     // Catch: java.lang.Throwable -> L2a
            r9.interrupt()     // Catch: java.lang.Throwable -> L2a
            java.io.InterruptedIOException r9 = new java.io.InterruptedIOException     // Catch: java.lang.Throwable -> L2a
            r9.<init>()     // Catch: java.lang.Throwable -> L2a
            throw r9     // Catch: java.lang.Throwable -> L2a
        L6a:
            monitor-exit(r8)
            throw r9
        L6c:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: J2.f.Y0(int, boolean, Q2.i, long):void");
    }

    public final void Z0(int i3, boolean z3, List list) {
        t2.j.f(list, "alternating");
        this.f1513A.y(z3, i3, list);
    }

    public final void a1(boolean z3, int i3, int i4) {
        try {
            this.f1513A.D(z3, i3, i4);
        } catch (IOException e3) {
            w0(e3);
        }
    }

    public final void b1(int i3, J2.b bVar) {
        t2.j.f(bVar, "statusCode");
        this.f1513A.W(i3, bVar);
    }

    public final void c1(int i3, J2.b bVar) {
        t2.j.f(bVar, "errorCode");
        F2.d dVar = this.f1524j;
        String str = this.f1519e + '[' + i3 + "] writeSynReset";
        dVar.i(new k(str, true, str, true, this, i3, bVar), 0L);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        v0(J2.b.NO_ERROR, J2.b.CANCEL, null);
    }

    public final void d1(int i3, long j3) {
        F2.d dVar = this.f1524j;
        String str = this.f1519e + '[' + i3 + "] windowUpdate";
        dVar.i(new l(str, true, str, true, this, i3, j3), 0L);
    }

    public final void flush() {
        this.f1513A.flush();
    }

    public final void v0(J2.b bVar, J2.b bVar2, IOException iOException) {
        int i3;
        J2.i[] iVarArr;
        t2.j.f(bVar, "connectionCode");
        t2.j.f(bVar2, "streamCode");
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
        try {
            U0(bVar);
        } catch (IOException unused) {
        }
        synchronized (this) {
            try {
                if (this.f1518d.isEmpty()) {
                    iVarArr = null;
                } else {
                    Object[] array = this.f1518d.values().toArray(new J2.i[0]);
                    if (array == null) {
                        throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
                    }
                    iVarArr = (J2.i[]) array;
                    this.f1518d.clear();
                }
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
        if (iVarArr != null) {
            for (J2.i iVar : iVarArr) {
                try {
                    iVar.d(bVar2, iOException);
                } catch (IOException unused2) {
                }
            }
        }
        try {
            this.f1513A.close();
        } catch (IOException unused3) {
        }
        try {
            this.f1540z.close();
        } catch (IOException unused4) {
        }
        this.f1524j.n();
        this.f1525k.n();
        this.f1526l.n();
    }

    public final boolean x0() {
        return this.f1516b;
    }

    public final String y0() {
        return this.f1519e;
    }

    public final int z0() {
        return this.f1520f;
    }

    public final class e implements h.c, InterfaceC0688a {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final J2.h f1555b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ f f1556c;

        public static final class a extends F2.a {

            /* JADX INFO: renamed from: e, reason: collision with root package name */
            final /* synthetic */ String f1557e;

            /* JADX INFO: renamed from: f, reason: collision with root package name */
            final /* synthetic */ boolean f1558f;

            /* JADX INFO: renamed from: g, reason: collision with root package name */
            final /* synthetic */ e f1559g;

            /* JADX INFO: renamed from: h, reason: collision with root package name */
            final /* synthetic */ t f1560h;

            /* JADX INFO: renamed from: i, reason: collision with root package name */
            final /* synthetic */ boolean f1561i;

            /* JADX INFO: renamed from: j, reason: collision with root package name */
            final /* synthetic */ m f1562j;

            /* JADX INFO: renamed from: k, reason: collision with root package name */
            final /* synthetic */ s f1563k;

            /* JADX INFO: renamed from: l, reason: collision with root package name */
            final /* synthetic */ t f1564l;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public a(String str, boolean z3, String str2, boolean z4, e eVar, t tVar, boolean z5, m mVar, s sVar, t tVar2) {
                super(str2, z4);
                this.f1557e = str;
                this.f1558f = z3;
                this.f1559g = eVar;
                this.f1560h = tVar;
                this.f1561i = z5;
                this.f1562j = mVar;
                this.f1563k = sVar;
                this.f1564l = tVar2;
            }

            @Override // F2.a
            public long f() {
                this.f1559g.f1556c.A0().a(this.f1559g.f1556c, (m) this.f1560h.f10216b);
                return -1L;
            }
        }

        public static final class b extends F2.a {

            /* JADX INFO: renamed from: e, reason: collision with root package name */
            final /* synthetic */ String f1565e;

            /* JADX INFO: renamed from: f, reason: collision with root package name */
            final /* synthetic */ boolean f1566f;

            /* JADX INFO: renamed from: g, reason: collision with root package name */
            final /* synthetic */ J2.i f1567g;

            /* JADX INFO: renamed from: h, reason: collision with root package name */
            final /* synthetic */ e f1568h;

            /* JADX INFO: renamed from: i, reason: collision with root package name */
            final /* synthetic */ J2.i f1569i;

            /* JADX INFO: renamed from: j, reason: collision with root package name */
            final /* synthetic */ int f1570j;

            /* JADX INFO: renamed from: k, reason: collision with root package name */
            final /* synthetic */ List f1571k;

            /* JADX INFO: renamed from: l, reason: collision with root package name */
            final /* synthetic */ boolean f1572l;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public b(String str, boolean z3, String str2, boolean z4, J2.i iVar, e eVar, J2.i iVar2, int i3, List list, boolean z5) {
                super(str2, z4);
                this.f1565e = str;
                this.f1566f = z3;
                this.f1567g = iVar;
                this.f1568h = eVar;
                this.f1569i = iVar2;
                this.f1570j = i3;
                this.f1571k = list;
                this.f1572l = z5;
            }

            @Override // F2.a
            public long f() {
                try {
                    this.f1568h.f1556c.A0().b(this.f1567g);
                    return -1L;
                } catch (IOException e3) {
                    L2.j.f1746c.g().k("Http2Connection.Listener failure for " + this.f1568h.f1556c.y0(), 4, e3);
                    try {
                        this.f1567g.d(J2.b.PROTOCOL_ERROR, e3);
                        return -1L;
                    } catch (IOException unused) {
                        return -1L;
                    }
                }
            }
        }

        public static final class c extends F2.a {

            /* JADX INFO: renamed from: e, reason: collision with root package name */
            final /* synthetic */ String f1573e;

            /* JADX INFO: renamed from: f, reason: collision with root package name */
            final /* synthetic */ boolean f1574f;

            /* JADX INFO: renamed from: g, reason: collision with root package name */
            final /* synthetic */ e f1575g;

            /* JADX INFO: renamed from: h, reason: collision with root package name */
            final /* synthetic */ int f1576h;

            /* JADX INFO: renamed from: i, reason: collision with root package name */
            final /* synthetic */ int f1577i;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public c(String str, boolean z3, String str2, boolean z4, e eVar, int i3, int i4) {
                super(str2, z4);
                this.f1573e = str;
                this.f1574f = z3;
                this.f1575g = eVar;
                this.f1576h = i3;
                this.f1577i = i4;
            }

            @Override // F2.a
            public long f() {
                this.f1575g.f1556c.a1(true, this.f1576h, this.f1577i);
                return -1L;
            }
        }

        public static final class d extends F2.a {

            /* JADX INFO: renamed from: e, reason: collision with root package name */
            final /* synthetic */ String f1578e;

            /* JADX INFO: renamed from: f, reason: collision with root package name */
            final /* synthetic */ boolean f1579f;

            /* JADX INFO: renamed from: g, reason: collision with root package name */
            final /* synthetic */ e f1580g;

            /* JADX INFO: renamed from: h, reason: collision with root package name */
            final /* synthetic */ boolean f1581h;

            /* JADX INFO: renamed from: i, reason: collision with root package name */
            final /* synthetic */ m f1582i;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public d(String str, boolean z3, String str2, boolean z4, e eVar, boolean z5, m mVar) {
                super(str2, z4);
                this.f1578e = str;
                this.f1579f = z3;
                this.f1580g = eVar;
                this.f1581h = z5;
                this.f1582i = mVar;
            }

            @Override // F2.a
            public long f() {
                this.f1580g.l(this.f1581h, this.f1582i);
                return -1L;
            }
        }

        public e(f fVar, J2.h hVar) {
            t2.j.f(hVar, "reader");
            this.f1556c = fVar;
            this.f1555b = hVar;
        }

        @Override // s2.InterfaceC0688a
        public /* bridge */ /* synthetic */ Object a() throws Throwable {
            m();
            return r.f9288a;
        }

        @Override // J2.h.c
        public void b(boolean z3, m mVar) {
            t2.j.f(mVar, "settings");
            F2.d dVar = this.f1556c.f1524j;
            String str = this.f1556c.y0() + " applyAndAckSettings";
            dVar.i(new d(str, true, str, true, this, z3, mVar), 0L);
        }

        @Override // J2.h.c
        public void c(boolean z3, int i3, Q2.k kVar, int i4) {
            t2.j.f(kVar, "source");
            if (this.f1556c.P0(i3)) {
                this.f1556c.L0(i3, kVar, i4, z3);
                return;
            }
            J2.i iVarE0 = this.f1556c.E0(i3);
            if (iVarE0 == null) {
                this.f1556c.c1(i3, J2.b.PROTOCOL_ERROR);
                long j3 = i4;
                this.f1556c.X0(j3);
                kVar.t(j3);
                return;
            }
            iVarE0.w(kVar, i4);
            if (z3) {
                iVarE0.x(C2.c.f579b, true);
            }
        }

        @Override // J2.h.c
        public void e(boolean z3, int i3, int i4) {
            if (!z3) {
                F2.d dVar = this.f1556c.f1524j;
                String str = this.f1556c.y0() + " ping";
                dVar.i(new c(str, true, str, true, this, i3, i4), 0L);
                return;
            }
            synchronized (this.f1556c) {
                try {
                    if (i3 == 1) {
                        this.f1556c.f1529o++;
                    } else if (i3 != 2) {
                        if (i3 == 3) {
                            this.f1556c.f1532r++;
                            f fVar = this.f1556c;
                            if (fVar == null) {
                                throw new NullPointerException("null cannot be cast to non-null type java.lang.Object");
                            }
                            fVar.notifyAll();
                        }
                        r rVar = r.f9288a;
                    } else {
                        this.f1556c.f1531q++;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        @Override // J2.h.c
        public void g(boolean z3, int i3, int i4, List list) {
            t2.j.f(list, "headerBlock");
            if (this.f1556c.P0(i3)) {
                this.f1556c.M0(i3, list, z3);
                return;
            }
            synchronized (this.f1556c) {
                J2.i iVarE0 = this.f1556c.E0(i3);
                if (iVarE0 != null) {
                    r rVar = r.f9288a;
                    iVarE0.x(C2.c.M(list), z3);
                    return;
                }
                if (this.f1556c.f1522h) {
                    return;
                }
                if (i3 <= this.f1556c.z0()) {
                    return;
                }
                if (i3 % 2 == this.f1556c.B0() % 2) {
                    return;
                }
                J2.i iVar = new J2.i(i3, this.f1556c, false, z3, C2.c.M(list));
                this.f1556c.S0(i3);
                this.f1556c.F0().put(Integer.valueOf(i3), iVar);
                F2.d dVarI = this.f1556c.f1523i.i();
                String str = this.f1556c.y0() + '[' + i3 + "] onStream";
                dVarI.i(new b(str, true, str, true, iVar, this, iVarE0, i3, list, z3), 0L);
            }
        }

        @Override // J2.h.c
        public void h(int i3, J2.b bVar) {
            t2.j.f(bVar, "errorCode");
            if (this.f1556c.P0(i3)) {
                this.f1556c.O0(i3, bVar);
                return;
            }
            J2.i iVarQ0 = this.f1556c.Q0(i3);
            if (iVarQ0 != null) {
                iVarQ0.y(bVar);
            }
        }

        @Override // J2.h.c
        public void i(int i3, long j3) {
            if (i3 != 0) {
                J2.i iVarE0 = this.f1556c.E0(i3);
                if (iVarE0 != null) {
                    synchronized (iVarE0) {
                        iVarE0.a(j3);
                        r rVar = r.f9288a;
                    }
                    return;
                }
                return;
            }
            synchronized (this.f1556c) {
                f fVar = this.f1556c;
                fVar.f1539y = fVar.G0() + j3;
                f fVar2 = this.f1556c;
                if (fVar2 == null) {
                    throw new NullPointerException("null cannot be cast to non-null type java.lang.Object");
                }
                fVar2.notifyAll();
                r rVar2 = r.f9288a;
            }
        }

        @Override // J2.h.c
        public void j(int i3, int i4, List list) {
            t2.j.f(list, "requestHeaders");
            this.f1556c.N0(i4, list);
        }

        @Override // J2.h.c
        public void k(int i3, J2.b bVar, Q2.l lVar) {
            int i4;
            J2.i[] iVarArr;
            t2.j.f(bVar, "errorCode");
            t2.j.f(lVar, "debugData");
            lVar.v();
            synchronized (this.f1556c) {
                Object[] array = this.f1556c.F0().values().toArray(new J2.i[0]);
                if (array == null) {
                    throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
                }
                iVarArr = (J2.i[]) array;
                this.f1556c.f1522h = true;
                r rVar = r.f9288a;
            }
            for (J2.i iVar : iVarArr) {
                if (iVar.j() > i3 && iVar.t()) {
                    iVar.y(J2.b.REFUSED_STREAM);
                    this.f1556c.Q0(iVar.j());
                }
            }
        }

        public final void l(boolean z3, m mVar) {
            f fVar;
            m mVar2;
            J2.i[] iVarArr;
            F2.d dVar;
            String str;
            t2.j.f(mVar, "settings");
            s sVar = new s();
            t tVar = new t();
            t tVar2 = new t();
            synchronized (this.f1556c.H0()) {
                f fVar2 = this.f1556c;
                synchronized (fVar2) {
                    try {
                        m mVarD0 = this.f1556c.D0();
                        if (z3) {
                            mVar2 = mVar;
                        } else {
                            mVar2 = new m();
                            mVar2.g(mVarD0);
                            mVar2.g(mVar);
                            r rVar = r.f9288a;
                        }
                        tVar2.f10216b = mVar2;
                        long jC = ((long) mVar2.c()) - ((long) mVarD0.c());
                        sVar.f10215b = jC;
                        if (jC == 0 || this.f1556c.F0().isEmpty()) {
                            iVarArr = null;
                        } else {
                            Object[] array = this.f1556c.F0().values().toArray(new J2.i[0]);
                            if (array == null) {
                                throw new NullPointerException("null cannot be cast to non-null type kotlin.Array<T>");
                            }
                            iVarArr = (J2.i[]) array;
                        }
                        tVar.f10216b = iVarArr;
                        this.f1556c.T0((m) tVar2.f10216b);
                        dVar = this.f1556c.f1526l;
                        str = this.f1556c.y0() + " onSettings";
                        fVar = fVar2;
                    } catch (Throwable th) {
                        th = th;
                        fVar = fVar2;
                    }
                    try {
                        dVar.i(new a(str, true, str, true, this, tVar2, z3, mVar, sVar, tVar), 0L);
                        r rVar2 = r.f9288a;
                        try {
                            this.f1556c.H0().b((m) tVar2.f10216b);
                        } catch (IOException e3) {
                            this.f1556c.w0(e3);
                        }
                        r rVar3 = r.f9288a;
                    } catch (Throwable th2) {
                        th = th2;
                        throw th;
                    }
                }
            }
            Object obj = tVar.f10216b;
            if (((J2.i[]) obj) != null) {
                J2.i[] iVarArr2 = (J2.i[]) obj;
                t2.j.c(iVarArr2);
                for (J2.i iVar : iVarArr2) {
                    synchronized (iVar) {
                        iVar.a(sVar.f10215b);
                        r rVar4 = r.f9288a;
                    }
                }
            }
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Type inference failed for: r0v0, types: [J2.b] */
        /* JADX WARN: Type inference failed for: r0v3 */
        /* JADX WARN: Type inference failed for: r0v5, types: [J2.h, java.io.Closeable] */
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
        public void m() throws Throwable {
            J2.b bVar;
            J2.b bVar2 = J2.b.INTERNAL_ERROR;
            IOException e3 = null;
            try {
                try {
                    this.f1555b.p(this);
                    while (this.f1555b.i(false, this)) {
                    }
                    J2.b bVar3 = J2.b.NO_ERROR;
                    try {
                        this.f1556c.v0(bVar3, J2.b.CANCEL, null);
                        bVar = bVar3;
                    } catch (IOException e4) {
                        e3 = e4;
                        J2.b bVar4 = J2.b.PROTOCOL_ERROR;
                        f fVar = this.f1556c;
                        fVar.v0(bVar4, bVar4, e3);
                        bVar = fVar;
                    }
                } catch (Throwable th) {
                    th = th;
                    this.f1556c.v0(bVar, bVar2, e3);
                    C2.c.j(this.f1555b);
                    throw th;
                }
            } catch (IOException e5) {
                e3 = e5;
            } catch (Throwable th2) {
                th = th2;
                bVar = bVar2;
                this.f1556c.v0(bVar, bVar2, e3);
                C2.c.j(this.f1555b);
                throw th;
            }
            bVar2 = this.f1555b;
            C2.c.j(bVar2);
        }

        @Override // J2.h.c
        public void d() {
        }

        @Override // J2.h.c
        public void f(int i3, int i4, int i5, boolean z3) {
        }
    }
}
