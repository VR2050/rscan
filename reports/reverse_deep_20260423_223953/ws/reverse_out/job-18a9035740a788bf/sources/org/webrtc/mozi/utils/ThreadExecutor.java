package org.webrtc.mozi.utils;

import android.os.Handler;
import android.os.Looper;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class ThreadExecutor {
    private static final int THREAD_GROUP_CONCURRENTS = 1;
    private static final String THREAD_GROUP_NAME = "mozi";
    private static ExecutorService sExecutorService;
    private static Handler sMainHandler = new Handler(Looper.getMainLooper());
    private static ScheduledExecutorService sScheduledExecutorService;

    public static void execute(Runnable runnable) {
        if (runnable == null) {
            return;
        }
        getExecutorService().execute(runnable);
    }

    public static void runOnMainThread(Runnable runnable) {
        if (runnable == null) {
            return;
        }
        if (Looper.getMainLooper().getThread() == Thread.currentThread()) {
            runnable.run();
        } else {
            sMainHandler.post(runnable);
        }
    }

    public static void runOnThread(Handler handler, Runnable runnable) {
        if (handler == null || runnable == null) {
            return;
        }
        if (Looper.myLooper() == handler.getLooper()) {
            runnable.run();
        } else {
            handler.post(runnable);
        }
    }

    public static Handler getMainHandler() {
        return sMainHandler;
    }

    public static ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
        return getScheduler().schedule(command, delay, unit);
    }

    public static ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
        return getScheduler().scheduleAtFixedRate(command, initialDelay, period, unit);
    }

    private static synchronized ScheduledExecutorService getScheduler() {
        if (sScheduledExecutorService == null) {
            sScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() { // from class: org.webrtc.mozi.utils.ThreadExecutor.1
                @Override // java.util.concurrent.ThreadFactory
                public Thread newThread(Runnable r) {
                    return new Thread(r, "mcs-executor");
                }
            });
        }
        return sScheduledExecutorService;
    }

    private static synchronized ExecutorService getExecutorService() {
        if (sExecutorService == null) {
            sExecutorService = Executors.newFixedThreadPool(1);
        }
        return sExecutorService;
    }
}
