package io.openinstall.sdk;

import android.app.Activity;
import android.text.TextUtils;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.webrtc.mozi.CodecMonitorHelper;

/* JADX INFO: loaded from: classes3.dex */
public class ds extends dp {
    private final WeakReference<Activity> c;
    private by d;
    private cx e;

    public ds(av avVar, WeakReference<Activity> weakReference) {
        super(avVar, null);
        this.c = weakReference;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public by a(by byVar) {
        if (byVar == null || byVar.c() == 0) {
            by byVarE = c().e();
            if (byVarE != null) {
                return byVarE;
            }
        } else {
            c().a(byVar);
        }
        return byVar;
    }

    private Map<String, Object> p() {
        int i;
        cv cvVar;
        Map<String, Object> mapSynchronizedMap = Collections.synchronizedMap(new HashMap());
        mapSynchronizedMap.put("ntrh", f().h());
        mapSynchronizedMap.put("regh", f().i());
        mapSynchronizedMap.put("mrth", f().j());
        mapSynchronizedMap.put("krtn", f().k());
        mapSynchronizedMap.put("fuqd", f().m());
        String strF = as.a().f();
        if (!TextUtils.isEmpty(strF)) {
            mapSynchronizedMap.put("gpde", strF);
        }
        LinkedBlockingQueue linkedBlockingQueue = new LinkedBlockingQueue();
        if (this.d == null) {
            j().execute(new dt(this, linkedBlockingQueue));
            i = 1;
        } else {
            h().a(false);
            by byVarA = a(this.d);
            if (byVarA.c(2)) {
                mapSynchronizedMap.put("pwcf", byVarA.b());
            } else if (byVarA.c(1)) {
                mapSynchronizedMap.put("aviw", byVarA.a());
            } else {
                mapSynchronizedMap.put("aviw", null);
            }
            i = 0;
        }
        int i2 = i + 1;
        j().execute(new du(this, linkedBlockingQueue));
        for (cw cwVar : this.e.a()) {
            if (cwVar.a()) {
                i2++;
                j().execute(new dv(this, linkedBlockingQueue, cwVar));
            } else {
                cv cvVarA_ = cwVar.a_();
                if (!TextUtils.isEmpty(cvVarA_.b()) && !TextUtils.isEmpty(cvVarA_.c())) {
                    mapSynchronizedMap.put(cvVarA_.b(), cvVarA_.c());
                }
            }
        }
        while (i2 > 0) {
            try {
                cvVar = (cv) linkedBlockingQueue.poll(1L, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                cvVar = null;
            }
            if (cvVar != null) {
                i2--;
                if (!TextUtils.isEmpty(cvVar.b()) && !TextUtils.isEmpty(cvVar.c())) {
                    mapSynchronizedMap.put(cvVar.b(), cvVar.c());
                    if (ec.a) {
                        ec.a(dz.getting_data.a(), cvVar.a());
                    }
                }
            }
        }
        return mapSynchronizedMap;
    }

    private void q() {
        String strA = TextUtils.isEmpty(d().h()) ? g().a(a()) : d().h();
        if (ec.a) {
            ec.a("opid = %s", strA);
        }
    }

    private void r() {
    }

    public void a(cx cxVar) {
        this.e = cxVar;
    }

    @Override // io.openinstall.sdk.cs
    protected String k() {
        return CodecMonitorHelper.EVENT_INIT;
    }

    @Override // io.openinstall.sdk.cs
    protected void m() {
        super.m();
        boolean zBooleanValue = as.a().g().booleanValue();
        by byVarA = by.a(as.a().h());
        boolean z = byVarA == null || byVarA.c() == 0;
        if (zBooleanValue && z) {
            System.currentTimeMillis();
            ar arVarA = c().a(as.a().e());
            if (arVarA == ar.a || arVarA == ar.c || arVarA == ar.e) {
                h().a(this.c);
                byVarA = h().b();
                System.currentTimeMillis();
            }
        }
        this.d = byVarA;
    }

    @Override // io.openinstall.sdk.dp
    protected cy o() {
        aq aqVarB;
        ar arVar;
        System.currentTimeMillis();
        ar arVarD = b().d();
        if (arVarD == null) {
            arVarD = c().a(a());
        }
        if (arVarD == ar.a) {
            c().k();
        }
        if (arVarD == ar.a || arVarD == ar.c || arVarD == ar.e) {
            b().a(ar.b);
            Map<String, Object> mapP = p();
            cr crVarA = e().a((Map<String, ?>) mapP);
            int iMin = 1;
            while (!crVarA.a()) {
                try {
                    b().a(iMin);
                } catch (InterruptedException e) {
                }
                crVarA = e().a((Map<String, ?>) mapP);
                iMin = Math.min(iMin * 2, 60);
            }
            cq cqVarE = crVarA.e();
            if (cqVarE.a() == 0) {
                c().b(cqVarE.c());
                c().c(cqVarE.b());
                aqVarB = b();
                arVar = ar.d;
            } else {
                c().c(cqVarE.b());
                if (cqVarE.a() == 1 || cqVarE.a() == 15) {
                    aqVarB = b();
                    arVar = ar.f;
                } else {
                    aqVarB = b();
                    arVar = ar.e;
                }
            }
            aqVarB.a(arVar);
            c().a((by) null);
            b().e();
            c().a(a(), b().d());
            q();
        } else if (arVarD == ar.d || arVarD == ar.f) {
            d().a(c().c());
            b().a(arVarD);
            b().e();
            h().a(false);
            q();
            r();
        }
        System.currentTimeMillis();
        return cy.a();
    }
}
