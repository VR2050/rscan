package org.webrtc.mozi.voiceengine.device;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.text.TextUtils;
import java.util.List;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes3.dex */
public class AudioAppBackgroundMonitor {
    private static final long CHECK_DELAY = 300;
    private static final String TAG = "AudioAppBackgroundMonitor";
    private boolean mForeground = false;
    private boolean mStoped = true;
    private HandlerThread mHandlerThread = new HandlerThread("DingRtcFrontBackThread");
    private Handler mHandler = null;
    private Application mApplication = null;
    private AudioAppBackgroundListener mListener = null;
    private Object mEventLock = new Object();
    private boolean mInitialize = false;
    private Runnable mCheckRunnable = new Runnable() { // from class: org.webrtc.mozi.voiceengine.device.AudioAppBackgroundMonitor.1
        @Override // java.lang.Runnable
        public void run() {
            if (AudioAppBackgroundMonitor.this.mForeground && AudioAppBackgroundMonitor.this.mStoped) {
                AudioAppBackgroundMonitor.this.mForeground = false;
                synchronized (AudioAppBackgroundMonitor.this.mEventLock) {
                    if (AudioAppBackgroundMonitor.this.mListener != null) {
                        AudioAppBackgroundMonitor.this.mListener.onEnterBackground();
                    }
                }
            }
        }
    };
    private Application.ActivityLifecycleCallbacks mLifecycleCallback = new Application.ActivityLifecycleCallbacks() { // from class: org.webrtc.mozi.voiceengine.device.AudioAppBackgroundMonitor.2
        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStarted(Activity activity) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityResumed(Activity activity) {
            try {
                AudioAppBackgroundMonitor.this.mStoped = false;
                boolean wasBackground = AudioAppBackgroundMonitor.this.mForeground ? false : true;
                AudioAppBackgroundMonitor.this.mForeground = true;
                if (AudioAppBackgroundMonitor.this.mCheckRunnable != null && AudioAppBackgroundMonitor.this.mHandler != null) {
                    AudioAppBackgroundMonitor.this.mHandler.removeCallbacks(AudioAppBackgroundMonitor.this.mCheckRunnable);
                }
                if (wasBackground) {
                    synchronized (AudioAppBackgroundMonitor.this.mEventLock) {
                        if (AudioAppBackgroundMonitor.this.mListener != null) {
                            AudioAppBackgroundMonitor.this.mListener.onEnterForeground();
                        }
                    }
                }
            } catch (Exception e) {
                Logging.e(AudioAppBackgroundMonitor.TAG, "onActivityResumed failed, error: " + e.getMessage());
            }
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPaused(Activity activity) {
            try {
                AudioAppBackgroundMonitor.this.mStoped = true;
                if (AudioAppBackgroundMonitor.this.mCheckRunnable != null && AudioAppBackgroundMonitor.this.mHandler != null) {
                    AudioAppBackgroundMonitor.this.mHandler.removeCallbacks(AudioAppBackgroundMonitor.this.mCheckRunnable);
                }
                if (AudioAppBackgroundMonitor.this.mHandler != null) {
                    AudioAppBackgroundMonitor.this.mHandler.postDelayed(AudioAppBackgroundMonitor.this.mCheckRunnable, AudioAppBackgroundMonitor.CHECK_DELAY);
                }
            } catch (Exception e) {
                Logging.e(AudioAppBackgroundMonitor.TAG, "onActivityPaused failed, error: " + e.getMessage());
            }
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStopped(Activity activity) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityDestroyed(Activity activity) {
        }
    };

    public interface AudioAppBackgroundListener {
        void onEnterBackground();

        void onEnterForeground();
    }

    public void setListener(AudioAppBackgroundListener listener) {
        synchronized (this.mEventLock) {
            this.mListener = listener;
        }
    }

    public void init(Application application) {
        if (this.mInitialize) {
            return;
        }
        this.mApplication = application;
        this.mHandlerThread.start();
        this.mHandler = new Handler(this.mHandlerThread.getLooper());
        this.mInitialize = true;
    }

    public void startMonitor() {
        if (!this.mInitialize) {
            return;
        }
        try {
            if (this.mApplication != null) {
                this.mApplication.registerActivityLifecycleCallbacks(this.mLifecycleCallback);
            }
        } catch (Exception e) {
            Logging.e(TAG, "startMonitor failed, error: " + e.getMessage());
        }
    }

    public void stopMonitor() {
        if (!this.mInitialize) {
            return;
        }
        try {
            if (this.mApplication != null) {
                this.mApplication.unregisterActivityLifecycleCallbacks(this.mLifecycleCallback);
            }
        } catch (Exception e) {
            Logging.e(TAG, "stopMonitor failed, error: " + e.getMessage());
        }
    }

    public void destroy() {
        if (!this.mInitialize) {
            return;
        }
        HandlerThread handlerThread = this.mHandlerThread;
        if (handlerThread != null) {
            handlerThread.quit();
        }
        if (this.mHandler != null) {
            this.mHandler = null;
        }
        if (this.mApplication != null) {
            this.mApplication = null;
        }
        this.mInitialize = false;
    }

    public static boolean isBackground(Context context) {
        ComponentName topActivity;
        try {
            ActivityManager am = (ActivityManager) context.getSystemService("activity");
            List<ActivityManager.RunningTaskInfo> tasks = am.getRunningTasks(1);
            if (tasks.isEmpty() || (topActivity = tasks.get(0).topActivity) == null || TextUtils.isEmpty(topActivity.getPackageName())) {
                return false;
            }
            return !topActivity.getPackageName().equals(context.getPackageName());
        } catch (Exception e) {
            Logging.e(TAG, "get background state failed, error: " + e.getMessage());
        }
        return false;
    }
}
