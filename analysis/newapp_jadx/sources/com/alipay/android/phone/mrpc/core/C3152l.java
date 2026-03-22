package com.alipay.android.phone.mrpc.core;

import android.content.Context;
import android.webkit.CookieManager;
import android.webkit.CookieSyncManager;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* renamed from: com.alipay.android.phone.mrpc.core.l */
/* loaded from: classes.dex */
public final class C3152l implements InterfaceC3139ab {

    /* renamed from: b */
    private static C3152l f8555b;

    /* renamed from: i */
    private static final ThreadFactory f8556i = new ThreadFactoryC3154n();

    /* renamed from: a */
    public Context f8557a;

    /* renamed from: c */
    private ThreadPoolExecutor f8558c;

    /* renamed from: d */
    private C3142b f8559d = C3142b.m3657a("android");

    /* renamed from: e */
    private long f8560e;

    /* renamed from: f */
    private long f8561f;

    /* renamed from: g */
    private long f8562g;

    /* renamed from: h */
    private int f8563h;

    private C3152l(Context context) {
        this.f8557a = context;
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(10, 11, 3L, TimeUnit.SECONDS, new ArrayBlockingQueue(20), f8556i, new ThreadPoolExecutor.CallerRunsPolicy());
        this.f8558c = threadPoolExecutor;
        try {
            threadPoolExecutor.allowCoreThreadTimeOut(true);
        } catch (Exception unused) {
        }
        CookieSyncManager.createInstance(this.f8557a);
        CookieManager.getInstance().setAcceptCookie(true);
    }

    /* renamed from: a */
    public static final C3152l m3681a(Context context) {
        C3152l c3152l = f8555b;
        return c3152l != null ? c3152l : m3682b(context);
    }

    /* renamed from: b */
    private static final synchronized C3152l m3682b(Context context) {
        synchronized (C3152l.class) {
            C3152l c3152l = f8555b;
            if (c3152l != null) {
                return c3152l;
            }
            C3152l c3152l2 = new C3152l(context);
            f8555b = c3152l2;
            return c3152l2;
        }
    }

    /* renamed from: a */
    public final C3142b m3683a() {
        return this.f8559d;
    }

    @Override // com.alipay.android.phone.mrpc.core.InterfaceC3139ab
    /* renamed from: a */
    public final Future<C3161u> mo3655a(AbstractC3160t abstractC3160t) {
        if (C3159s.m3718a(this.f8557a)) {
            String str = "HttpManager" + hashCode() + ": Active Task = %d, Completed Task = %d, All Task = %d,Avarage Speed = %d KB/S, Connetct Time = %d ms, All data size = %d bytes, All enqueueConnect time = %d ms, All socket time = %d ms, All request times = %d times";
            Object[] objArr = new Object[9];
            objArr[0] = Integer.valueOf(this.f8558c.getActiveCount());
            objArr[1] = Long.valueOf(this.f8558c.getCompletedTaskCount());
            objArr[2] = Long.valueOf(this.f8558c.getTaskCount());
            long j2 = this.f8562g;
            objArr[3] = Long.valueOf(j2 == 0 ? 0L : ((this.f8560e * 1000) / j2) >> 10);
            int i2 = this.f8563h;
            objArr[4] = Long.valueOf(i2 != 0 ? this.f8561f / i2 : 0L);
            objArr[5] = Long.valueOf(this.f8560e);
            objArr[6] = Long.valueOf(this.f8561f);
            objArr[7] = Long.valueOf(this.f8562g);
            objArr[8] = Integer.valueOf(this.f8563h);
            String.format(str, objArr);
        }
        CallableC3157q callableC3157q = new CallableC3157q(this, (C3155o) abstractC3160t);
        C3153m c3153m = new C3153m(this, callableC3157q, callableC3157q);
        this.f8558c.execute(c3153m);
        return c3153m;
    }

    /* renamed from: a */
    public final void m3684a(long j2) {
        this.f8560e += j2;
    }

    /* renamed from: b */
    public final void m3685b(long j2) {
        this.f8561f += j2;
        this.f8563h++;
    }

    /* renamed from: c */
    public final void m3686c(long j2) {
        this.f8562g += j2;
    }
}
