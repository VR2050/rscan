package com.ding.rtc.task;

import android.os.Handler;
import android.os.Looper;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;

/* JADX INFO: loaded from: classes.dex */
public class TaskExecutor {
    private static final HashMap<Runnable, Runnable> sDelayTasks = new HashMap<>();
    private static volatile TaskExecutor sTaskExecutor;
    private final Handler mMainThreadHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService mExecutor = new TaskThreadPoolExecutor(true);

    public static TaskExecutor getInstance() {
        if (sTaskExecutor == null) {
            synchronized (TaskExecutor.class) {
                sTaskExecutor = new TaskExecutor();
            }
        }
        return sTaskExecutor;
    }

    private static ExecutorService getExecutor() {
        return getInstance().mExecutor;
    }

    public static Handler getMainThreadHandler() {
        return getInstance().mMainThreadHandler;
    }

    public static void execute(Runnable runnable) {
        execute(runnable, 0L);
    }

    public static void execute(final Runnable runnable, long delayMillisecond) {
        if (runnable == null || delayMillisecond < 0 || getExecutor().isShutdown()) {
            return;
        }
        if (delayMillisecond > 0) {
            Runnable delayRunnable = new Runnable() { // from class: com.ding.rtc.task.TaskExecutor.1
                @Override // java.lang.Runnable
                public void run() {
                    synchronized (TaskExecutor.sDelayTasks) {
                        TaskExecutor.sDelayTasks.remove(runnable);
                    }
                    TaskExecutor.realExecute(runnable);
                }
            };
            synchronized (sDelayTasks) {
                sDelayTasks.put(runnable, delayRunnable);
            }
            getMainThreadHandler().postDelayed(delayRunnable, delayMillisecond);
            return;
        }
        realExecute(runnable);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void realExecute(Runnable runnable) {
        getExecutor().execute(runnable);
    }

    public static void removeTask(final Runnable runnable) {
        Runnable delayRunnable;
        if (runnable == null) {
            return;
        }
        synchronized (sDelayTasks) {
            delayRunnable = sDelayTasks.remove(runnable);
        }
        if (delayRunnable != null) {
            getMainThreadHandler().removeCallbacks(delayRunnable);
        }
    }

    public static void postToMainThread(final Runnable task) {
        postToMainThread(task, 0L);
    }

    public static void postToMainThread(final Runnable task, long delayMillis) {
        if (task == null) {
            return;
        }
        getMainThreadHandler().postDelayed(task, delayMillis);
    }

    public static void removeMainThreadRunnable(Runnable task) {
        if (task == null) {
            return;
        }
        getMainThreadHandler().removeCallbacks(task);
    }

    public static boolean isMainThread() {
        return Thread.currentThread() == getInstance().mMainThreadHandler.getLooper().getThread();
    }
}
