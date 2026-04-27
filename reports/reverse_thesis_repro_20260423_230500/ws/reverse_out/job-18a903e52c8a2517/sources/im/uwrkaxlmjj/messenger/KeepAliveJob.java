package im.uwrkaxlmjj.messenger;

import android.content.Intent;
import com.google.android.exoplayer2.upstream.DefaultLoadErrorHandlingPolicy;
import im.uwrkaxlmjj.messenger.support.JobIntentService;
import java.util.concurrent.CountDownLatch;

/* JADX INFO: loaded from: classes2.dex */
public class KeepAliveJob extends JobIntentService {
    private static volatile CountDownLatch countDownLatch;
    private static volatile boolean startingJob;
    private static final Object sync = new Object();
    private static Runnable finishJobByTimeoutRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.KeepAliveJob.3
        @Override // java.lang.Runnable
        public void run() {
            KeepAliveJob.finishJobInternal();
        }
    };

    public static void startJob() {
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.KeepAliveJob.1
            @Override // java.lang.Runnable
            public void run() {
                if (KeepAliveJob.startingJob || KeepAliveJob.countDownLatch != null) {
                    return;
                }
                try {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("starting keep-alive job");
                    }
                    synchronized (KeepAliveJob.sync) {
                        boolean unused = KeepAliveJob.startingJob = true;
                    }
                    JobIntentService.enqueueWork(ApplicationLoader.applicationContext, KeepAliveJob.class, 1000, new Intent());
                } catch (Exception e) {
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void finishJobInternal() {
        synchronized (sync) {
            if (countDownLatch != null) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("finish keep-alive job");
                }
                countDownLatch.countDown();
            }
            if (startingJob) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("finish queued keep-alive job");
                }
                startingJob = false;
            }
        }
    }

    public static void finishJob() {
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.KeepAliveJob.2
            @Override // java.lang.Runnable
            public void run() {
                KeepAliveJob.finishJobInternal();
            }
        });
    }

    @Override // im.uwrkaxlmjj.messenger.support.JobIntentService
    protected void onHandleWork(Intent intent) {
        synchronized (sync) {
            if (startingJob) {
                countDownLatch = new CountDownLatch(1);
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("started keep-alive job");
                }
                Utilities.globalQueue.postRunnable(finishJobByTimeoutRunnable, DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS);
                try {
                    countDownLatch.await();
                } catch (Throwable th) {
                }
                Utilities.globalQueue.cancelRunnable(finishJobByTimeoutRunnable);
                synchronized (sync) {
                    countDownLatch = null;
                }
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("ended keep-alive job");
                }
            }
        }
    }
}
