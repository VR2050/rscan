package im.uwrkaxlmjj.ui.hui.visualcall;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: loaded from: classes5.dex */
public class ThreadUtils {
    private static final int CORE_POOL_SIZE;
    private static final int CPU_COUNT;
    private static final int KEEP_ALIVE_SECONDS = 30;
    private static final int MAXIMUM_POOL_SIZE;
    private static final BlockingQueue<Runnable> POOL_WORK_QUEUE;
    private static final ThreadFactory THREAD_FACTORY;
    private static final ThreadPoolExecutor THREAD_POOL_EXECUTOR;
    private static Handler sMainHandler = new Handler(Looper.getMainLooper());
    private static final String TAG = ThreadUtils.class.getName();

    static {
        int iAvailableProcessors = Runtime.getRuntime().availableProcessors();
        CPU_COUNT = iAvailableProcessors;
        CORE_POOL_SIZE = Math.max(2, Math.min(iAvailableProcessors - 1, 4));
        MAXIMUM_POOL_SIZE = (CPU_COUNT * 2) + 1;
        POOL_WORK_QUEUE = new LinkedBlockingQueue(128);
        THREAD_FACTORY = new ThreadFactory() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.ThreadUtils.1
            private final AtomicInteger mCount = new AtomicInteger(1);

            @Override // java.util.concurrent.ThreadFactory
            public Thread newThread(Runnable r) {
                return new Thread(r, "ThreadUtils #" + this.mCount.getAndIncrement());
            }
        };
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(CORE_POOL_SIZE, MAXIMUM_POOL_SIZE, 30L, TimeUnit.SECONDS, POOL_WORK_QUEUE, THREAD_FACTORY);
        threadPoolExecutor.allowCoreThreadTimeOut(true);
        THREAD_POOL_EXECUTOR = threadPoolExecutor;
    }

    public static void runOnUiThread(Runnable runnable) {
        runOnUiThread(runnable, 0L);
    }

    public static void runOnUiThread(Runnable runnable, long delayed) {
        sMainHandler.postDelayed(runnable, delayed);
    }

    public static void runOnSubThread(Runnable runnable) {
        if (THREAD_POOL_EXECUTOR.getQueue().size() == 128 || THREAD_POOL_EXECUTOR.isShutdown()) {
            Log.e(TAG, "线程池爆满警告，请查看是否开启了过多的耗时线程");
        } else {
            THREAD_POOL_EXECUTOR.execute(runnable);
        }
    }
}
