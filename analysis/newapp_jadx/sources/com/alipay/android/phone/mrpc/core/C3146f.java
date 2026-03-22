package com.alipay.android.phone.mrpc.core;

import org.apache.http.HttpResponse;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.protocol.HttpContext;

/* renamed from: com.alipay.android.phone.mrpc.core.f */
/* loaded from: classes.dex */
public final class C3146f implements ConnectionKeepAliveStrategy {

    /* renamed from: a */
    public final /* synthetic */ C3144d f8545a;

    public C3146f(C3144d c3144d) {
        this.f8545a = c3144d;
    }

    @Override // org.apache.http.conn.ConnectionKeepAliveStrategy
    public final long getKeepAliveDuration(HttpResponse httpResponse, HttpContext httpContext) {
        return 180000L;
    }
}
