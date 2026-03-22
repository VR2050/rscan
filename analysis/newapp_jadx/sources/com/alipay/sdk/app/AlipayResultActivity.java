package com.alipay.sdk.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.json.JSONObject;
import p005b.p085c.p088b.p089a.C1346c;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p098h.C1373a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class AlipayResultActivity extends Activity {

    /* renamed from: c */
    public static final ConcurrentHashMap<String, InterfaceC3191a> f8655c = new ConcurrentHashMap<>();

    /* renamed from: com.alipay.sdk.app.AlipayResultActivity$a */
    public interface InterfaceC3191a {
        /* renamed from: a */
        void mo426a(int i2, String str, String str2);
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        Intent intent;
        C1373a c1373a;
        String stringExtra;
        Bundle bundleExtra;
        String stringExtra2;
        super.onCreate(bundle);
        try {
            intent = getIntent();
            c1373a = null;
            try {
                stringExtra = intent.getStringExtra("session");
                bundleExtra = intent.getBundleExtra("result");
                stringExtra2 = intent.getStringExtra("scene");
                HashMap<UUID, C1373a> hashMap = C1373a.a.f1256a;
                if (!TextUtils.isEmpty(stringExtra)) {
                    c1373a = C1373a.a.f1257b.remove(stringExtra);
                }
            } catch (Throwable th) {
                C1353c.m363d(null, "biz", "BSPSerError", th);
                C1353c.m363d(null, "biz", "ParseBundleSerializableError", th);
                return;
            }
        } catch (Throwable unused) {
        }
        if (c1373a == null) {
            return;
        }
        C1353c.m367h(c1373a, "biz", "BSPSession", stringExtra + "|" + SystemClock.elapsedRealtime());
        if (TextUtils.equals("mqpSchemePay", stringExtra2)) {
            InterfaceC3191a remove = f8655c.remove(stringExtra);
            if (remove == null) {
                return;
            }
            try {
                remove.mo426a(bundleExtra.getInt("endCode"), bundleExtra.getString("memo"), bundleExtra.getString("result"));
                return;
            } finally {
                finish();
            }
        }
        if ((TextUtils.isEmpty(stringExtra) || bundleExtra == null) && intent.getData() != null) {
            try {
                JSONObject jSONObject = new JSONObject(new String(Base64.decode(intent.getData().getQuery(), 2), "UTF-8"));
                JSONObject jSONObject2 = jSONObject.getJSONObject("result");
                stringExtra = jSONObject.getString("session");
                C1353c.m367h(c1373a, "biz", "BSPUriSession", stringExtra);
                Bundle bundle2 = new Bundle();
                try {
                    Iterator<String> keys = jSONObject2.keys();
                    while (keys.hasNext()) {
                        String next = keys.next();
                        bundle2.putString(next, jSONObject2.getString(next));
                    }
                    bundleExtra = bundle2;
                } catch (Throwable th2) {
                    th = th2;
                    bundleExtra = bundle2;
                    C1353c.m363d(c1373a, "biz", "BSPResEx", th);
                    C1353c.m363d(c1373a, "biz", "ParseSchemeQueryError", th);
                    if (TextUtils.isEmpty(stringExtra)) {
                    }
                    C1353c.m366g(this, c1373a, "", c1373a.f1250d);
                    finish();
                    return;
                }
            } catch (Throwable th3) {
                th = th3;
            }
        }
        if (!TextUtils.isEmpty(stringExtra) || bundleExtra == null) {
            C1353c.m366g(this, c1373a, "", c1373a.f1250d);
            finish();
            return;
        }
        try {
            C1353c.m367h(c1373a, "biz", "PgReturn", "" + SystemClock.elapsedRealtime());
            C1353c.m367h(c1373a, "biz", "PgReturnV", bundleExtra.getInt("endCode", -1) + "|" + bundleExtra.getString("memo", "-"));
            C1346c.a remove2 = C1346c.f1163a.remove(stringExtra);
            if (remove2 != null) {
                try {
                    remove2.m354a(9000, "OK", bundleExtra);
                } catch (Throwable th4) {
                    C4195m.m4816l(th4);
                }
            }
            C1353c.m366g(this, c1373a, "", c1373a.f1250d);
            finish();
        } catch (Throwable th5) {
            C1353c.m366g(this, c1373a, "", c1373a.f1250d);
            throw th5;
        }
    }
}
