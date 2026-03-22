package com.alipay.sdk.app;

import p005b.p085c.p088b.p100j.C1380e;

/* loaded from: classes.dex */
public class H5AuthActivity extends H5PayActivity {
    @Override // com.alipay.sdk.app.H5PayActivity
    /* renamed from: a */
    public void mo3832a() {
        synchronized (C1380e.class) {
            try {
                C1380e.class.notify();
            } catch (Exception unused) {
            }
        }
    }
}
