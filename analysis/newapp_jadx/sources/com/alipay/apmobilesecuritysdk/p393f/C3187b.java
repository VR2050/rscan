package com.alipay.apmobilesecuritysdk.p393f;

import java.util.LinkedList;

/* renamed from: com.alipay.apmobilesecuritysdk.f.b */
/* loaded from: classes.dex */
public final class C3187b {

    /* renamed from: a */
    private static C3187b f8638a = new C3187b();

    /* renamed from: b */
    private Thread f8639b = null;

    /* renamed from: c */
    private LinkedList<Runnable> f8640c = new LinkedList<>();

    /* renamed from: a */
    public static C3187b m3822a() {
        return f8638a;
    }

    /* renamed from: b */
    public static /* synthetic */ Thread m3824b(C3187b c3187b) {
        c3187b.f8639b = null;
        return null;
    }

    /* renamed from: a */
    public final synchronized void m3825a(Runnable runnable) {
        this.f8640c.add(runnable);
        if (this.f8639b == null) {
            Thread thread = new Thread(new RunnableC3188c(this));
            this.f8639b = thread;
            thread.start();
        }
    }
}
