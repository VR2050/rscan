package com.alipay.sdk.app;

import android.content.Intent;
import android.net.Uri;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p098h.C1373a;

/* loaded from: classes.dex */
public class H5OpenAuthActivity extends H5PayActivity {

    /* renamed from: k */
    public boolean f8658k = false;

    @Override // com.alipay.sdk.app.H5PayActivity
    /* renamed from: a */
    public void mo3832a() {
    }

    @Override // com.alipay.sdk.app.H5PayActivity, android.app.Activity
    public void onDestroy() {
        if (this.f8658k) {
            try {
                C1373a m415a = C1373a.a.m415a(getIntent());
                if (m415a != null) {
                    C1353c.m366g(this, m415a, "", m415a.f1250d);
                }
            } catch (Throwable unused) {
            }
        }
        super.onDestroy();
    }

    @Override // android.app.Activity, android.content.ContextWrapper, android.content.Context
    public void startActivity(Intent intent) {
        try {
            C1373a m415a = C1373a.a.m415a(intent);
            if (m415a == null) {
                finish();
                return;
            }
            try {
                super.startActivity(intent);
                Uri data = intent != null ? intent.getData() : null;
                if (data == null || !data.toString().startsWith("alipays://platformapi/startapp")) {
                    return;
                }
                finish();
            } catch (Throwable th) {
                C1353c.m364e(m415a, "biz", "StartActivityEx", th, (intent == null || intent.getData() == null) ? "null" : intent.getData().toString());
                this.f8658k = true;
                throw th;
            }
        } catch (Throwable unused) {
            finish();
        }
    }
}
