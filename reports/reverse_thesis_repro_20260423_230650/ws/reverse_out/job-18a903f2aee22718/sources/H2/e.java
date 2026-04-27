package H2;

import B2.D;
import B2.m;
import B2.n;
import B2.t;
import B2.u;
import Q2.l;
import java.io.EOFException;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public abstract class e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final l f1076a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final l f1077b;

    static {
        l.a aVar = l.f2556f;
        f1076a = aVar.e("\"\\");
        f1077b = aVar.e("\t ,=");
    }

    public static final List a(t tVar, String str) {
        t2.j.f(tVar, "$this$parseChallenges");
        t2.j.f(str, "headerName");
        ArrayList arrayList = new ArrayList();
        int size = tVar.size();
        for (int i3 = 0; i3 < size; i3++) {
            if (z2.g.j(str, tVar.b(i3), true)) {
                try {
                    c(new Q2.i().j0(tVar.h(i3)), arrayList);
                } catch (EOFException e3) {
                    L2.j.f1746c.g().k("Unable to parse challenge", 5, e3);
                }
            }
        }
        return arrayList;
    }

    public static final boolean b(D d3) {
        t2.j.f(d3, "$this$promisesBody");
        if (t2.j.b(d3.y0().h(), "HEAD")) {
            return false;
        }
        int iA = d3.A();
        return (((iA >= 100 && iA < 200) || iA == 204 || iA == 304) && C2.c.s(d3) == -1 && !z2.g.j("chunked", D.d0(d3, "Transfer-Encoding", null, 2, null), true)) ? false : true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:59:0x0085, code lost:
    
        continue;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0085, code lost:
    
        continue;
     */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0090  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static final void c(Q2.i r7, java.util.List r8) throws java.io.EOFException {
        /*
            r0 = 0
        L1:
            r1 = r0
        L2:
            if (r1 != 0) goto Le
            g(r7)
            java.lang.String r1 = e(r7)
            if (r1 != 0) goto Le
            return
        Le:
            boolean r2 = g(r7)
            java.lang.String r3 = e(r7)
            if (r3 != 0) goto L2c
            boolean r7 = r7.K()
            if (r7 != 0) goto L1f
            return
        L1f:
            B2.h r7 = new B2.h
            java.util.Map r0 = i2.D.f()
            r7.<init>(r1, r0)
            r8.add(r7)
            return
        L2c:
            r4 = 61
            byte r4 = (byte) r4
            int r5 = C2.c.I(r7, r4)
            boolean r6 = g(r7)
            if (r2 != 0) goto L68
            if (r6 != 0) goto L41
            boolean r2 = r7.K()
            if (r2 == 0) goto L68
        L41:
            B2.h r2 = new B2.h
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            r4.<init>()
            r4.append(r3)
            java.lang.String r3 = "="
            java.lang.String r3 = z2.g.m(r3, r5)
            r4.append(r3)
            java.lang.String r3 = r4.toString()
            java.util.Map r3 = java.util.Collections.singletonMap(r0, r3)
            java.lang.String r4 = "Collections.singletonMap…ek + \"=\".repeat(eqCount))"
            t2.j.e(r3, r4)
            r2.<init>(r1, r3)
            r8.add(r2)
            goto L1
        L68:
            java.util.LinkedHashMap r2 = new java.util.LinkedHashMap
            r2.<init>()
            int r6 = C2.c.I(r7, r4)
            int r5 = r5 + r6
        L72:
            if (r3 != 0) goto L83
            java.lang.String r3 = e(r7)
            boolean r5 = g(r7)
            if (r5 == 0) goto L7f
            goto L85
        L7f:
            int r5 = C2.c.I(r7, r4)
        L83:
            if (r5 != 0) goto L90
        L85:
            B2.h r4 = new B2.h
            r4.<init>(r1, r2)
            r8.add(r4)
            r1 = r3
            goto L2
        L90:
            r6 = 1
            if (r5 <= r6) goto L94
            return
        L94:
            boolean r6 = g(r7)
            if (r6 == 0) goto L9b
            return
        L9b:
            r6 = 34
            byte r6 = (byte) r6
            boolean r6 = h(r7, r6)
            if (r6 == 0) goto La9
            java.lang.String r6 = d(r7)
            goto Lad
        La9:
            java.lang.String r6 = e(r7)
        Lad:
            if (r6 == 0) goto Lc7
            java.lang.Object r3 = r2.put(r3, r6)
            java.lang.String r3 = (java.lang.String) r3
            if (r3 == 0) goto Lb8
            return
        Lb8:
            boolean r3 = g(r7)
            if (r3 != 0) goto Lc5
            boolean r3 = r7.K()
            if (r3 != 0) goto Lc5
            return
        Lc5:
            r3 = r0
            goto L72
        Lc7:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: H2.e.c(Q2.i, java.util.List):void");
    }

    private static final String d(Q2.i iVar) throws EOFException {
        byte b3 = (byte) 34;
        if (!(iVar.r0() == b3)) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        Q2.i iVar2 = new Q2.i();
        while (true) {
            long jN0 = iVar.n0(f1076a);
            if (jN0 == -1) {
                return null;
            }
            if (iVar.Z(jN0) == b3) {
                iVar2.m(iVar, jN0);
                iVar.r0();
                return iVar2.O();
            }
            if (iVar.F0() == jN0 + 1) {
                return null;
            }
            iVar2.m(iVar, jN0);
            iVar.r0();
            iVar2.m(iVar, 1L);
        }
    }

    private static final String e(Q2.i iVar) {
        long jN0 = iVar.n0(f1077b);
        if (jN0 == -1) {
            jN0 = iVar.F0();
        }
        if (jN0 != 0) {
            return iVar.D0(jN0);
        }
        return null;
    }

    public static final void f(n nVar, u uVar, t tVar) {
        t2.j.f(nVar, "$this$receiveHeaders");
        t2.j.f(uVar, "url");
        t2.j.f(tVar, "headers");
        if (nVar == n.f388a) {
            return;
        }
        List listE = m.f369n.e(uVar, tVar);
        if (listE.isEmpty()) {
            return;
        }
        nVar.b(uVar, listE);
    }

    private static final boolean g(Q2.i iVar) throws EOFException {
        boolean z3 = false;
        while (!iVar.K()) {
            byte bZ = iVar.Z(0L);
            if (bZ == 9 || bZ == 32) {
                iVar.r0();
            } else {
                if (bZ != 44) {
                    break;
                }
                iVar.r0();
                z3 = true;
            }
        }
        return z3;
    }

    private static final boolean h(Q2.i iVar, byte b3) {
        return !iVar.K() && iVar.Z(0L) == b3;
    }
}
