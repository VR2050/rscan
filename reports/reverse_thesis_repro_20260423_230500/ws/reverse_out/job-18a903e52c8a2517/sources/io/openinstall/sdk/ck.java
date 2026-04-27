package io.openinstall.sdk;

import android.text.TextUtils;
import android.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class ck {
    private static volatile ck a;
    private final cj b;
    private final av c;
    private ci d;
    private ch e;
    private CountDownLatch f = null;
    private String g;
    private String h;
    private Map<String, String> i;

    private ck(av avVar, cj cjVar) {
        this.c = avVar;
        this.b = cjVar;
    }

    public static ck a(av avVar) {
        if (a == null) {
            synchronized (ck.class) {
                if (a == null) {
                    a = new ck(avVar, new cj());
                }
            }
        }
        return a;
    }

    private void a(cr crVar) {
        if (crVar.a()) {
            String strD = crVar.e().d();
            if (TextUtils.isEmpty(strD)) {
                return;
            }
            aw awVarB = aw.b(strD);
            aw awVarF = this.c.f();
            if (!awVarF.equals(awVarB)) {
                awVarF.a(awVarB);
                this.c.d().a(awVarF);
            }
            if (TextUtils.isEmpty(awVarF.h())) {
                return;
            }
            this.c.i().b(as.a().e(), awVarF.h());
        }
    }

    private synchronized Map<String, String> b() {
        if (this.i == null) {
            this.i = this.d.a_();
        }
        return this.i;
    }

    private void b(cp cpVar) {
        if (this.f != null) {
            System.currentTimeMillis();
            try {
                this.f.await(3L, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
            }
        }
        String strB = cpVar.g() ? this.g : this.h;
        if (cpVar.f() != null) {
            strB = cpVar.f();
        }
        if (strB == null || strB.isEmpty()) {
            strB = cpVar.g() ? this.e.b() : this.e.c();
        }
        cpVar.b(strB);
    }

    private void b(cr crVar) {
        if (crVar.a()) {
            int iA = crVar.e().a();
            if (iA == 1 || iA == 15) {
                this.c.d().c(true);
            }
        }
    }

    private Map<String, Object> c() {
        HashMap map = new HashMap(b());
        aw awVarF = this.c.f();
        map.put("f3ef", TextUtils.isEmpty(awVarF.h()) ? this.c.i().a(as.a().e()) : awVarF.h());
        map.put("qmvzs", String.valueOf(System.currentTimeMillis()));
        return map;
    }

    public cr a(cp cpVar) throws Throwable {
        if (this.c.d().j()) {
            return new cr(new Exception("request forbidden"));
        }
        cpVar.a(c());
        b(cpVar);
        cr crVarA = this.b.a(cpVar, 5000);
        a(crVarA);
        b(crVarA);
        if (crVarA.f()) {
            this.e.a();
        }
        return crVarA;
    }

    public cr a(Map<String, ?> map) {
        cp cpVar = new cp(true, "/init");
        cpVar.b(map);
        return a(cpVar);
    }

    public String a(String str) {
        return this.b.a(new cn(str), 3000).d();
    }

    public void a() {
        this.f = new CountDownLatch(1);
    }

    public void a(ch chVar) {
        this.e = chVar;
    }

    public void a(ci ciVar) {
        this.d = ciVar;
    }

    public void a(String str, String str2) {
        if (str != null && str.contains("api2.")) {
            str = str.replace("api2.", "api2-" + as.a().e() + ".");
        }
        this.g = str;
        if (str2 == null || !str2.contains("stat2.")) {
            this.h = str2;
        } else {
            this.h = str2.replace("stat2.", "stat2-" + as.a().e() + ".");
        }
        CountDownLatch countDownLatch = this.f;
        if (countDownLatch != null) {
            countDownLatch.countDown();
        }
    }

    public cr b(String str) {
        co coVar = new co(false, "/stats/events");
        coVar.a(str);
        return a(coVar);
    }

    public cr b(Map<String, ?> map) {
        cp cpVar = new cp(true, "/decode-wakeup-url");
        cpVar.b(map);
        return a(cpVar);
    }

    public cr c(Map<String, ?> map) {
        cp cpVar = new cp(false, "/stats/wakeup");
        cpVar.b(map);
        return a(cpVar);
    }

    public cr d(Map<String, ?> map) {
        cp cpVar = new cp(false, "/share/report");
        cpVar.b(map);
        return a(cpVar);
    }

    public cr e(Map<String, ?> map) {
        cp cpVar = new cp(true, "/status");
        try {
            cpVar.b(new String(Base64.decode("c3RhZXZlbnQueHl6", 0), "UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        cpVar.b(map);
        return a(cpVar);
    }
}
