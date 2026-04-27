package J2;

import B2.A;
import B2.B;
import B2.D;
import B2.t;
import B2.z;
import Q2.F;
import Q2.G;
import java.io.IOException;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class g implements H2.d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private volatile i f1622a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final A f1623b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private volatile boolean f1624c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final G2.f f1625d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final H2.g f1626e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final f f1627f;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final a f1621i = new a(null);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final List f1619g = C2.c.t("connection", "host", "keep-alive", "proxy-connection", "te", "transfer-encoding", "encoding", "upgrade", ":method", ":path", ":scheme", ":authority");

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final List f1620h = C2.c.t("connection", "host", "keep-alive", "proxy-connection", "te", "transfer-encoding", "encoding", "upgrade");

    public static final class a {
        private a() {
        }

        public final List a(B b3) {
            t2.j.f(b3, "request");
            t tVarE = b3.e();
            ArrayList arrayList = new ArrayList(tVarE.size() + 4);
            arrayList.add(new c(c.f1477f, b3.h()));
            arrayList.add(new c(c.f1478g, H2.i.f1091a.c(b3.l())));
            String strD = b3.d("Host");
            if (strD != null) {
                arrayList.add(new c(c.f1480i, strD));
            }
            arrayList.add(new c(c.f1479h, b3.l().p()));
            int size = tVarE.size();
            for (int i3 = 0; i3 < size; i3++) {
                String strB = tVarE.b(i3);
                Locale locale = Locale.US;
                t2.j.e(locale, "Locale.US");
                if (strB == null) {
                    throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
                }
                String lowerCase = strB.toLowerCase(locale);
                t2.j.e(lowerCase, "(this as java.lang.String).toLowerCase(locale)");
                if (!g.f1619g.contains(lowerCase) || (t2.j.b(lowerCase, "te") && t2.j.b(tVarE.h(i3), "trailers"))) {
                    arrayList.add(new c(lowerCase, tVarE.h(i3)));
                }
            }
            return arrayList;
        }

        public final D.a b(t tVar, A a3) throws ProtocolException {
            t2.j.f(tVar, "headerBlock");
            t2.j.f(a3, "protocol");
            t.a aVar = new t.a();
            int size = tVar.size();
            H2.k kVarA = null;
            for (int i3 = 0; i3 < size; i3++) {
                String strB = tVar.b(i3);
                String strH = tVar.h(i3);
                if (t2.j.b(strB, ":status")) {
                    kVarA = H2.k.f1094d.a("HTTP/1.1 " + strH);
                } else if (!g.f1620h.contains(strB)) {
                    aVar.c(strB, strH);
                }
            }
            if (kVarA != null) {
                return new D.a().p(a3).g(kVarA.f1096b).m(kVarA.f1097c).k(aVar.e());
            }
            throw new ProtocolException("Expected ':status' header not present");
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public g(z zVar, G2.f fVar, H2.g gVar, f fVar2) {
        t2.j.f(zVar, "client");
        t2.j.f(fVar, "connection");
        t2.j.f(gVar, "chain");
        t2.j.f(fVar2, "http2Connection");
        this.f1625d = fVar;
        this.f1626e = gVar;
        this.f1627f = fVar2;
        List listF = zVar.F();
        A a3 = A.H2_PRIOR_KNOWLEDGE;
        this.f1623b = listF.contains(a3) ? a3 : A.HTTP_2;
    }

    @Override // H2.d
    public long a(D d3) {
        t2.j.f(d3, "response");
        if (H2.e.b(d3)) {
            return C2.c.s(d3);
        }
        return 0L;
    }

    @Override // H2.d
    public Q2.D b(B b3, long j3) {
        t2.j.f(b3, "request");
        i iVar = this.f1622a;
        t2.j.c(iVar);
        return iVar.n();
    }

    @Override // H2.d
    public void c() {
        i iVar = this.f1622a;
        t2.j.c(iVar);
        iVar.n().close();
    }

    @Override // H2.d
    public void cancel() {
        this.f1624c = true;
        i iVar = this.f1622a;
        if (iVar != null) {
            iVar.f(b.CANCEL);
        }
    }

    @Override // H2.d
    public void d() {
        this.f1627f.flush();
    }

    @Override // H2.d
    public void e(B b3) throws IOException {
        t2.j.f(b3, "request");
        if (this.f1622a != null) {
            return;
        }
        this.f1622a = this.f1627f.K0(f1621i.a(b3), b3.a() != null);
        if (this.f1624c) {
            i iVar = this.f1622a;
            t2.j.c(iVar);
            iVar.f(b.CANCEL);
            throw new IOException("Canceled");
        }
        i iVar2 = this.f1622a;
        t2.j.c(iVar2);
        G gV = iVar2.v();
        long jG = this.f1626e.g();
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        gV.g(jG, timeUnit);
        i iVar3 = this.f1622a;
        t2.j.c(iVar3);
        iVar3.E().g(this.f1626e.j(), timeUnit);
    }

    @Override // H2.d
    public F f(D d3) {
        t2.j.f(d3, "response");
        i iVar = this.f1622a;
        t2.j.c(iVar);
        return iVar.p();
    }

    @Override // H2.d
    public D.a g(boolean z3) throws ProtocolException {
        i iVar = this.f1622a;
        t2.j.c(iVar);
        D.a aVarB = f1621i.b(iVar.C(), this.f1623b);
        if (z3 && aVarB.h() == 100) {
            return null;
        }
        return aVarB;
    }

    @Override // H2.d
    public G2.f h() {
        return this.f1625d;
    }
}
