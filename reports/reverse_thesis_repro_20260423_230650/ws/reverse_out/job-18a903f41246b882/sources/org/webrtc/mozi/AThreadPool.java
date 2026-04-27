package org.webrtc.mozi;

import android.util.Log;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;

/* JADX INFO: loaded from: classes3.dex */
public class AThreadPool {
    private static final String TAG = "AThreadPool";
    private static volatile ScheduledThreadPoolExecutor glExecutor;

    private static ScheduledThreadPoolExecutor getGlExecutor() {
        if (glExecutor == null) {
            synchronized (AThreadPool.class) {
                if (glExecutor == null) {
                    glExecutor = new ScheduledThreadPoolExecutor(1, new ThreadFactory() { // from class: org.webrtc.mozi.AThreadPool.1
                        @Override // java.util.concurrent.ThreadFactory
                        public Thread newThread(Runnable r) {
                            Thread thread = new Thread(r, "AGLthread");
                            thread.setPriority(5);
                            return thread;
                        }
                    });
                }
            }
        }
        return glExecutor;
    }

    public static void executeGL(Runnable r) {
        try {
            getGlExecutor().execute(r);
        } catch (Throwable t) {
            Log.e(TAG, "executeGL", t);
        }
    }
}
