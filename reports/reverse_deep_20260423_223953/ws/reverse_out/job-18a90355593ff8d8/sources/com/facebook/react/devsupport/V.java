package com.facebook.react.devsupport;

import java.io.EOFException;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
class V {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Q2.k f6786a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f6787b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long f6788c;

    public interface a {
        void a(Map map, long j3, long j4);

        void b(Map map, Q2.i iVar, boolean z3);
    }

    public V(Q2.k kVar, String str) {
        this.f6786a = kVar;
        this.f6787b = str;
    }

    private void a(Q2.i iVar, boolean z3, a aVar) throws EOFException {
        long jE0 = iVar.e0(Q2.l.e("\r\n\r\n"));
        if (jE0 == -1) {
            aVar.b(null, iVar, z3);
            return;
        }
        Q2.i iVar2 = new Q2.i();
        Q2.i iVar3 = new Q2.i();
        iVar.R(iVar2, jE0);
        iVar.t(r0.v());
        iVar.h0(iVar3);
        aVar.b(c(iVar2), iVar3, z3);
    }

    private void b(Map map, long j3, boolean z3, a aVar) {
        if (map == null || aVar == null) {
            return;
        }
        long jCurrentTimeMillis = System.currentTimeMillis();
        if (jCurrentTimeMillis - this.f6788c > 16 || z3) {
            this.f6788c = jCurrentTimeMillis;
            aVar.a(map, j3, map.get("Content-Length") != null ? Long.parseLong((String) map.get("Content-Length")) : 0L);
        }
    }

    private Map c(Q2.i iVar) {
        HashMap map = new HashMap();
        for (String str : iVar.O().split("\r\n")) {
            int iIndexOf = str.indexOf(":");
            if (iIndexOf != -1) {
                map.put(str.substring(0, iIndexOf).trim(), str.substring(iIndexOf + 1).trim());
            }
        }
        return map;
    }

    public boolean d(a aVar) throws EOFException {
        boolean z3;
        long j3;
        Q2.l lVarE = Q2.l.e("\r\n--" + this.f6787b + "\r\n");
        Q2.l lVarE2 = Q2.l.e("\r\n--" + this.f6787b + "--\r\n");
        Q2.l lVarE3 = Q2.l.e("\r\n\r\n");
        Q2.i iVar = new Q2.i();
        long j4 = 0L;
        long jV = 0L;
        long jF0 = 0L;
        Map mapC = null;
        while (true) {
            long jMax = Math.max(j4 - ((long) lVarE2.v()), jV);
            long jF02 = iVar.f0(lVarE, jMax);
            if (jF02 == -1) {
                jF02 = iVar.f0(lVarE2, jMax);
                z3 = true;
            } else {
                z3 = false;
            }
            if (jF02 == -1) {
                long jF03 = iVar.F0();
                if (mapC == null) {
                    long jF04 = iVar.f0(lVarE3, jMax);
                    if (jF04 >= 0) {
                        this.f6786a.R(iVar, jF04);
                        Q2.i iVar2 = new Q2.i();
                        j3 = jV;
                        iVar.D(iVar2, jMax, jF04 - jMax);
                        jF0 = iVar2.F0() + ((long) lVarE3.v());
                        mapC = c(iVar2);
                    } else {
                        j3 = jV;
                    }
                } else {
                    j3 = jV;
                    b(mapC, iVar.F0() - jF0, false, aVar);
                }
                if (this.f6786a.R(iVar, 4096) <= 0) {
                    return false;
                }
                j4 = jF03;
                jV = j3;
            } else {
                long j5 = jV;
                long j6 = jF02 - j5;
                if (j5 > 0) {
                    Q2.i iVar3 = new Q2.i();
                    iVar.t(j5);
                    iVar.R(iVar3, j6);
                    b(mapC, iVar3.F0() - jF0, true, aVar);
                    a(iVar3, z3, aVar);
                    jF0 = 0;
                    mapC = null;
                } else {
                    iVar.t(jF02);
                }
                if (z3) {
                    return true;
                }
                jV = lVarE.v();
                j4 = jV;
            }
        }
    }
}
