package J2;

import Q2.F;
import Q2.t;
import i2.AbstractC0580h;
import i2.AbstractC0586n;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final c[] f1485a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Map f1486b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final d f1487c;

    static {
        d dVar = new d();
        f1487c = dVar;
        c cVar = new c(c.f1480i, "");
        Q2.l lVar = c.f1477f;
        c cVar2 = new c(lVar, "GET");
        c cVar3 = new c(lVar, "POST");
        Q2.l lVar2 = c.f1478g;
        c cVar4 = new c(lVar2, "/");
        c cVar5 = new c(lVar2, "/index.html");
        Q2.l lVar3 = c.f1479h;
        c cVar6 = new c(lVar3, "http");
        c cVar7 = new c(lVar3, "https");
        Q2.l lVar4 = c.f1476e;
        f1485a = new c[]{cVar, cVar2, cVar3, cVar4, cVar5, cVar6, cVar7, new c(lVar4, "200"), new c(lVar4, "204"), new c(lVar4, "206"), new c(lVar4, "304"), new c(lVar4, "400"), new c(lVar4, "404"), new c(lVar4, "500"), new c("accept-charset", ""), new c("accept-encoding", "gzip, deflate"), new c("accept-language", ""), new c("accept-ranges", ""), new c("accept", ""), new c("access-control-allow-origin", ""), new c("age", ""), new c("allow", ""), new c("authorization", ""), new c("cache-control", ""), new c("content-disposition", ""), new c("content-encoding", ""), new c("content-language", ""), new c("content-length", ""), new c("content-location", ""), new c("content-range", ""), new c("content-type", ""), new c("cookie", ""), new c("date", ""), new c("etag", ""), new c("expect", ""), new c("expires", ""), new c("from", ""), new c("host", ""), new c("if-match", ""), new c("if-modified-since", ""), new c("if-none-match", ""), new c("if-range", ""), new c("if-unmodified-since", ""), new c("last-modified", ""), new c("link", ""), new c("location", ""), new c("max-forwards", ""), new c("proxy-authenticate", ""), new c("proxy-authorization", ""), new c("range", ""), new c("referer", ""), new c("refresh", ""), new c("retry-after", ""), new c("server", ""), new c("set-cookie", ""), new c("strict-transport-security", ""), new c("transfer-encoding", ""), new c("user-agent", ""), new c("vary", ""), new c("via", ""), new c("www-authenticate", "")};
        f1486b = dVar.d();
    }

    private d() {
    }

    private final Map d() {
        c[] cVarArr = f1485a;
        LinkedHashMap linkedHashMap = new LinkedHashMap(cVarArr.length);
        int length = cVarArr.length;
        for (int i3 = 0; i3 < length; i3++) {
            c[] cVarArr2 = f1485a;
            if (!linkedHashMap.containsKey(cVarArr2[i3].f1483b)) {
                linkedHashMap.put(cVarArr2[i3].f1483b, Integer.valueOf(i3));
            }
        }
        Map mapUnmodifiableMap = Collections.unmodifiableMap(linkedHashMap);
        t2.j.e(mapUnmodifiableMap, "Collections.unmodifiableMap(result)");
        return mapUnmodifiableMap;
    }

    public final Q2.l a(Q2.l lVar) throws IOException {
        t2.j.f(lVar, "name");
        int iV = lVar.v();
        for (int i3 = 0; i3 < iV; i3++) {
            byte b3 = (byte) 65;
            byte b4 = (byte) 90;
            byte bF = lVar.f(i3);
            if (b3 <= bF && b4 >= bF) {
                throw new IOException("PROTOCOL_ERROR response malformed: mixed case name: " + lVar.z());
            }
        }
        return lVar;
    }

    public final Map b() {
        return f1486b;
    }

    public final c[] c() {
        return f1485a;
    }

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final List f1488a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Q2.k f1489b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public c[] f1490c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f1491d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public int f1492e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        public int f1493f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final int f1494g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private int f1495h;

        public a(F f3, int i3, int i4) {
            t2.j.f(f3, "source");
            this.f1494g = i3;
            this.f1495h = i4;
            this.f1488a = new ArrayList();
            this.f1489b = t.d(f3);
            this.f1490c = new c[8];
            this.f1491d = r2.length - 1;
        }

        private final void a() {
            int i3 = this.f1495h;
            int i4 = this.f1493f;
            if (i3 < i4) {
                if (i3 == 0) {
                    b();
                } else {
                    d(i4 - i3);
                }
            }
        }

        private final void b() {
            AbstractC0580h.k(this.f1490c, null, 0, 0, 6, null);
            this.f1491d = this.f1490c.length - 1;
            this.f1492e = 0;
            this.f1493f = 0;
        }

        private final int c(int i3) {
            return this.f1491d + 1 + i3;
        }

        private final int d(int i3) {
            int i4;
            int i5 = 0;
            if (i3 > 0) {
                int length = this.f1490c.length;
                while (true) {
                    length--;
                    i4 = this.f1491d;
                    if (length < i4 || i3 <= 0) {
                        break;
                    }
                    c cVar = this.f1490c[length];
                    t2.j.c(cVar);
                    int i6 = cVar.f1482a;
                    i3 -= i6;
                    this.f1493f -= i6;
                    this.f1492e--;
                    i5++;
                }
                c[] cVarArr = this.f1490c;
                System.arraycopy(cVarArr, i4 + 1, cVarArr, i4 + 1 + i5, this.f1492e);
                this.f1491d += i5;
            }
            return i5;
        }

        private final Q2.l f(int i3) throws IOException {
            if (h(i3)) {
                return d.f1487c.c()[i3].f1483b;
            }
            int iC = c(i3 - d.f1487c.c().length);
            if (iC >= 0) {
                c[] cVarArr = this.f1490c;
                if (iC < cVarArr.length) {
                    c cVar = cVarArr[iC];
                    t2.j.c(cVar);
                    return cVar.f1483b;
                }
            }
            throw new IOException("Header index too large " + (i3 + 1));
        }

        private final void g(int i3, c cVar) {
            this.f1488a.add(cVar);
            int i4 = cVar.f1482a;
            if (i3 != -1) {
                c cVar2 = this.f1490c[c(i3)];
                t2.j.c(cVar2);
                i4 -= cVar2.f1482a;
            }
            int i5 = this.f1495h;
            if (i4 > i5) {
                b();
                return;
            }
            int iD = d((this.f1493f + i4) - i5);
            if (i3 == -1) {
                int i6 = this.f1492e + 1;
                c[] cVarArr = this.f1490c;
                if (i6 > cVarArr.length) {
                    c[] cVarArr2 = new c[cVarArr.length * 2];
                    System.arraycopy(cVarArr, 0, cVarArr2, cVarArr.length, cVarArr.length);
                    this.f1491d = this.f1490c.length - 1;
                    this.f1490c = cVarArr2;
                }
                int i7 = this.f1491d;
                this.f1491d = i7 - 1;
                this.f1490c[i7] = cVar;
                this.f1492e++;
            } else {
                this.f1490c[i3 + c(i3) + iD] = cVar;
            }
            this.f1493f += i4;
        }

        private final boolean h(int i3) {
            return i3 >= 0 && i3 <= d.f1487c.c().length - 1;
        }

        private final int i() {
            return C2.c.b(this.f1489b.r0(), 255);
        }

        private final void l(int i3) throws IOException {
            if (h(i3)) {
                this.f1488a.add(d.f1487c.c()[i3]);
                return;
            }
            int iC = c(i3 - d.f1487c.c().length);
            if (iC >= 0) {
                c[] cVarArr = this.f1490c;
                if (iC < cVarArr.length) {
                    List list = this.f1488a;
                    c cVar = cVarArr[iC];
                    t2.j.c(cVar);
                    list.add(cVar);
                    return;
                }
            }
            throw new IOException("Header index too large " + (i3 + 1));
        }

        private final void n(int i3) {
            g(-1, new c(f(i3), j()));
        }

        private final void o() {
            g(-1, new c(d.f1487c.a(j()), j()));
        }

        private final void p(int i3) throws IOException {
            this.f1488a.add(new c(f(i3), j()));
        }

        private final void q() throws IOException {
            this.f1488a.add(new c(d.f1487c.a(j()), j()));
        }

        public final List e() {
            List listT = AbstractC0586n.T(this.f1488a);
            this.f1488a.clear();
            return listT;
        }

        public final Q2.l j() {
            int i3 = i();
            boolean z3 = (i3 & 128) == 128;
            long jM = m(i3, 127);
            if (!z3) {
                return this.f1489b.q(jM);
            }
            Q2.i iVar = new Q2.i();
            k.f1679d.b(this.f1489b, jM, iVar);
            return iVar.z0();
        }

        public final void k() throws IOException {
            while (!this.f1489b.K()) {
                int iB = C2.c.b(this.f1489b.r0(), 255);
                if (iB == 128) {
                    throw new IOException("index == 0");
                }
                if ((iB & 128) == 128) {
                    l(m(iB, 127) - 1);
                } else if (iB == 64) {
                    o();
                } else if ((iB & 64) == 64) {
                    n(m(iB, 63) - 1);
                } else if ((iB & 32) == 32) {
                    int iM = m(iB, 31);
                    this.f1495h = iM;
                    if (iM < 0 || iM > this.f1494g) {
                        throw new IOException("Invalid dynamic table size update " + this.f1495h);
                    }
                    a();
                } else if (iB == 16 || iB == 0) {
                    q();
                } else {
                    p(m(iB, 15) - 1);
                }
            }
        }

        public final int m(int i3, int i4) {
            int i5 = i3 & i4;
            if (i5 < i4) {
                return i5;
            }
            int i6 = 0;
            while (true) {
                int i7 = i();
                if ((i7 & 128) == 0) {
                    return i4 + (i7 << i6);
                }
                i4 += (i7 & 127) << i6;
                i6 += 7;
            }
        }

        public /* synthetic */ a(F f3, int i3, int i4, int i5, DefaultConstructorMarker defaultConstructorMarker) {
            this(f3, i3, (i5 & 4) != 0 ? i3 : i4);
        }
    }

    public static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f1496a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f1497b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public int f1498c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public c[] f1499d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f1500e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        public int f1501f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        public int f1502g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        public int f1503h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final boolean f1504i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private final Q2.i f1505j;

        public b(int i3, boolean z3, Q2.i iVar) {
            t2.j.f(iVar, "out");
            this.f1503h = i3;
            this.f1504i = z3;
            this.f1505j = iVar;
            this.f1496a = Integer.MAX_VALUE;
            this.f1498c = i3;
            this.f1499d = new c[8];
            this.f1500e = r2.length - 1;
        }

        private final void a() {
            int i3 = this.f1498c;
            int i4 = this.f1502g;
            if (i3 < i4) {
                if (i3 == 0) {
                    b();
                } else {
                    c(i4 - i3);
                }
            }
        }

        private final void b() {
            AbstractC0580h.k(this.f1499d, null, 0, 0, 6, null);
            this.f1500e = this.f1499d.length - 1;
            this.f1501f = 0;
            this.f1502g = 0;
        }

        private final int c(int i3) {
            int i4;
            int i5 = 0;
            if (i3 > 0) {
                int length = this.f1499d.length;
                while (true) {
                    length--;
                    i4 = this.f1500e;
                    if (length < i4 || i3 <= 0) {
                        break;
                    }
                    c cVar = this.f1499d[length];
                    t2.j.c(cVar);
                    i3 -= cVar.f1482a;
                    int i6 = this.f1502g;
                    c cVar2 = this.f1499d[length];
                    t2.j.c(cVar2);
                    this.f1502g = i6 - cVar2.f1482a;
                    this.f1501f--;
                    i5++;
                }
                c[] cVarArr = this.f1499d;
                System.arraycopy(cVarArr, i4 + 1, cVarArr, i4 + 1 + i5, this.f1501f);
                c[] cVarArr2 = this.f1499d;
                int i7 = this.f1500e;
                Arrays.fill(cVarArr2, i7 + 1, i7 + 1 + i5, (Object) null);
                this.f1500e += i5;
            }
            return i5;
        }

        private final void d(c cVar) {
            int i3 = cVar.f1482a;
            int i4 = this.f1498c;
            if (i3 > i4) {
                b();
                return;
            }
            c((this.f1502g + i3) - i4);
            int i5 = this.f1501f + 1;
            c[] cVarArr = this.f1499d;
            if (i5 > cVarArr.length) {
                c[] cVarArr2 = new c[cVarArr.length * 2];
                System.arraycopy(cVarArr, 0, cVarArr2, cVarArr.length, cVarArr.length);
                this.f1500e = this.f1499d.length - 1;
                this.f1499d = cVarArr2;
            }
            int i6 = this.f1500e;
            this.f1500e = i6 - 1;
            this.f1499d[i6] = cVar;
            this.f1501f++;
            this.f1502g += i3;
        }

        public final void e(int i3) {
            this.f1503h = i3;
            int iMin = Math.min(i3, 16384);
            int i4 = this.f1498c;
            if (i4 == iMin) {
                return;
            }
            if (iMin < i4) {
                this.f1496a = Math.min(this.f1496a, iMin);
            }
            this.f1497b = true;
            this.f1498c = iMin;
            a();
        }

        public final void f(Q2.l lVar) {
            t2.j.f(lVar, "data");
            if (this.f1504i) {
                k kVar = k.f1679d;
                if (kVar.d(lVar) < lVar.v()) {
                    Q2.i iVar = new Q2.i();
                    kVar.c(lVar, iVar);
                    Q2.l lVarZ0 = iVar.z0();
                    h(lVarZ0.v(), 127, 128);
                    this.f1505j.z(lVarZ0);
                    return;
                }
            }
            h(lVar.v(), 127, 0);
            this.f1505j.z(lVar);
        }

        /* JADX WARN: Removed duplicated region for block: B:23:0x0077  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final void g(java.util.List r13) {
            /*
                Method dump skipped, instruction units count: 264
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: J2.d.b.g(java.util.List):void");
        }

        public final void h(int i3, int i4, int i5) {
            if (i3 < i4) {
                this.f1505j.L(i3 | i5);
                return;
            }
            this.f1505j.L(i5 | i4);
            int i6 = i3 - i4;
            while (i6 >= 128) {
                this.f1505j.L(128 | (i6 & 127));
                i6 >>>= 7;
            }
            this.f1505j.L(i6);
        }

        public /* synthetic */ b(int i3, boolean z3, Q2.i iVar, int i4, DefaultConstructorMarker defaultConstructorMarker) {
            this((i4 & 1) != 0 ? 4096 : i3, (i4 & 2) != 0 ? true : z3, iVar);
        }
    }
}
