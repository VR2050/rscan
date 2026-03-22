package com.alipay.sdk.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import p005b.p085c.p088b.p089a.C1344a;
import p005b.p085c.p088b.p089a.C1348e;
import p005b.p085c.p088b.p089a.C1349f;
import p005b.p085c.p088b.p089a.EnumC1350g;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p092c.C1356a;
import p005b.p085c.p088b.p095f.p096d.C1366a;
import p005b.p085c.p088b.p097g.C1372b;
import p005b.p085c.p088b.p097g.EnumC1371a;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p085c.p088b.p098h.C1374b;
import p005b.p085c.p088b.p100j.C1380e;
import p005b.p085c.p088b.p100j.C1381f;
import p005b.p085c.p088b.p100j.C1383h;
import p005b.p085c.p088b.p101k.C1385b;
import p005b.p085c.p088b.p101k.RunnableC1384a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class AuthTask {

    /* renamed from: a */
    public Activity f8656a;

    /* renamed from: b */
    public C1385b f8657b;

    public AuthTask(Activity activity) {
        this.f8656a = activity;
        C1374b.m417a().m418b(this.f8656a);
        this.f8657b = new C1385b(activity, "去支付宝授权");
    }

    /* renamed from: a */
    public final String m3828a(Activity activity, String str, C1373a c1373a) {
        String m410a = c1373a.m410a(str);
        List<C1356a.b> list = C1356a.m376d().f1211p;
        Objects.requireNonNull(C1356a.m376d());
        if (!C1383h.m447k(c1373a, this.f8656a, C1348e.f1168d)) {
            C1353c.m361b(c1373a, "biz", "LogCalledH5");
            return m3830c(activity, m410a, c1373a);
        }
        String m428b = new C1380e(activity, c1373a, new C1344a(this)).m428b(m410a);
        if (!TextUtils.equals(m428b, "failed") && !TextUtils.equals(m428b, "scheme_failed")) {
            return TextUtils.isEmpty(m428b) ? C1349f.m357b() : m428b;
        }
        C1353c.m361b(c1373a, "biz", "LogBindCalledH5");
        return m3830c(activity, m410a, c1373a);
    }

    public synchronized String auth(String str, boolean z) {
        return innerAuth(new C1373a(this.f8656a, str, "auth"), str, z);
    }

    public synchronized Map<String, String> authV2(String str, boolean z) {
        C1373a c1373a;
        c1373a = new C1373a(this.f8656a, str, "authV2");
        return C1381f.m431c(c1373a, innerAuth(c1373a, str, z));
    }

    /* renamed from: b */
    public final String m3829b(C1373a c1373a, C1372b c1372b) {
        String[] strArr = c1372b.f1246b;
        Bundle bundle = new Bundle();
        bundle.putString("url", strArr[0]);
        Intent intent = new Intent(this.f8656a, (Class<?>) H5AuthActivity.class);
        intent.putExtras(bundle);
        C1373a.a.m416b(c1373a, intent);
        this.f8656a.startActivity(intent);
        synchronized (C1380e.class) {
            try {
                C1380e.class.wait();
            } catch (InterruptedException unused) {
                return C1349f.m357b();
            }
        }
        String str = C1349f.f1170b;
        return TextUtils.isEmpty(str) ? C1349f.m357b() : str;
    }

    /* renamed from: c */
    public final String m3830c(Activity activity, String str, C1373a c1373a) {
        Activity activity2;
        C1385b c1385b = this.f8657b;
        if (c1385b != null && (activity2 = c1385b.f1310b) != null) {
            activity2.runOnUiThread(new RunnableC1384a(c1385b));
        }
        EnumC1350g enumC1350g = null;
        try {
            try {
                try {
                    List<C1372b> m407a = C1372b.m407a(new C1366a().mo399a(c1373a, activity, str).m395a().optJSONObject("form").optJSONObject("onload"));
                    m3831d();
                    int i2 = 0;
                    while (true) {
                        ArrayList arrayList = (ArrayList) m407a;
                        if (i2 >= arrayList.size()) {
                            break;
                        }
                        if (((C1372b) arrayList.get(i2)).f1245a == EnumC1371a.WapPay) {
                            String m3829b = m3829b(c1373a, (C1372b) arrayList.get(i2));
                            m3831d();
                            return m3829b;
                        }
                        i2++;
                    }
                } catch (IOException e2) {
                    enumC1350g = EnumC1350g.m358a(6002);
                    C1353c.m365f(c1373a, "net", e2);
                }
            } catch (Throwable th) {
                C1353c.m363d(c1373a, "biz", "H5AuthDataAnalysisError", th);
            }
            m3831d();
            if (enumC1350g == null) {
                enumC1350g = EnumC1350g.m358a(4000);
            }
            return C1349f.m356a(enumC1350g.f1179l, enumC1350g.f1180m, "");
        } catch (Throwable th2) {
            m3831d();
            throw th2;
        }
    }

    /* renamed from: d */
    public final void m3831d() {
        C1385b c1385b = this.f8657b;
        if (c1385b != null) {
            c1385b.m455a();
        }
    }

    public synchronized String innerAuth(C1373a c1373a, String str, boolean z) {
        Activity activity;
        String m357b;
        Activity activity2;
        if (z) {
            C1385b c1385b = this.f8657b;
            if (c1385b != null && (activity = c1385b.f1310b) != null) {
                activity.runOnUiThread(new RunnableC1384a(c1385b));
            }
        }
        C1374b.m417a().m418b(this.f8656a);
        m357b = C1349f.m357b();
        C1348e.m355a("");
        try {
            try {
                m357b = m3828a(this.f8656a, str, c1373a);
                C1353c.m367h(c1373a, "biz", "PgReturn", "" + SystemClock.elapsedRealtime());
                C1353c.m367h(c1373a, "biz", "PgReturnV", C1381f.m430b(m357b, "resultStatus") + "|" + C1381f.m430b(m357b, "memo"));
                if (!C1356a.m376d().f1210o) {
                    C1356a.m376d().m378b(c1373a, this.f8656a);
                }
                m3831d();
                activity2 = this.f8656a;
            } catch (Exception e2) {
                C4195m.m4816l(e2);
                C1353c.m367h(c1373a, "biz", "PgReturn", "" + SystemClock.elapsedRealtime());
                C1353c.m367h(c1373a, "biz", "PgReturnV", C1381f.m430b(m357b, "resultStatus") + "|" + C1381f.m430b(m357b, "memo"));
                if (!C1356a.m376d().f1210o) {
                    C1356a.m376d().m378b(c1373a, this.f8656a);
                }
                m3831d();
                activity2 = this.f8656a;
            }
            C1353c.m366g(activity2, c1373a, str, c1373a.f1250d);
        } catch (Throwable th) {
            C1353c.m367h(c1373a, "biz", "PgReturn", "" + SystemClock.elapsedRealtime());
            C1353c.m367h(c1373a, "biz", "PgReturnV", C1381f.m430b(m357b, "resultStatus") + "|" + C1381f.m430b(m357b, "memo"));
            if (!C1356a.m376d().f1210o) {
                C1356a.m376d().m378b(c1373a, this.f8656a);
            }
            m3831d();
            C1353c.m366g(this.f8656a, c1373a, str, c1373a.f1250d);
            throw th;
        }
        return m357b;
    }
}
