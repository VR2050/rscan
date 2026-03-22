package com.alipay.android.phone.mrpc.core;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.alipay.android.phone.mrpc.core.n */
/* loaded from: classes.dex */
public final class ThreadFactoryC3154n implements ThreadFactory {

    /* renamed from: a */
    private final AtomicInteger f8566a = new AtomicInteger(1);

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        Thread thread = new Thread(runnable, "com.alipay.mobile.common.transport.http.HttpManager.HttpWorker #" + this.f8566a.getAndIncrement());
        thread.setPriority(4);
        return thread;
    }
}
