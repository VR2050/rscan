package io.openinstall.sdk;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class db {
    private static final ThreadFactory a = new dc();
    private static final RejectedExecutionHandler b = new de();
    private static final ThreadPoolExecutor c = new ThreadPoolExecutor(5, 10, 10, TimeUnit.SECONDS, new LinkedBlockingQueue(30), a, b);
    private static final ThreadPoolExecutor d = new ThreadPoolExecutor(3, 10, 10, TimeUnit.SECONDS, new LinkedBlockingQueue(30), a, b);

    static {
        c.allowCoreThreadTimeOut(true);
        d.allowCoreThreadTimeOut(true);
    }

    public static ThreadPoolExecutor a() {
        return d;
    }

    public static ThreadPoolExecutor b() {
        return c;
    }
}
