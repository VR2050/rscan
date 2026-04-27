package com.ding.rtc.monitor;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Application;
import android.app.KeyguardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.text.TextUtils;
import android.util.Log;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class AppFrontBackHelper {
    public static final long CHECK_DELAY = 500;
    public static final String TAG = AppFrontBackHelper.class.getName();
    private Runnable check;
    private OnAppStatusListener mListener;
    private boolean foreground = false;
    private boolean stoped = true;
    private final HandlerThread mHandlerThread = new HandlerThread("AlivcForntBackThread");
    private Handler handler = null;
    private Application.ActivityLifecycleCallbacks mLifecycleCallback = new Application.ActivityLifecycleCallbacks() { // from class: com.ding.rtc.monitor.AppFrontBackHelper.1
        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStarted(Activity activity) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityResumed(Activity activity) {
            AppFrontBackHelper.this.stoped = false;
            boolean wasBackground = !AppFrontBackHelper.this.foreground;
            AppFrontBackHelper.this.foreground = true;
            if (AppFrontBackHelper.this.check != null && AppFrontBackHelper.this.handler != null) {
                AppFrontBackHelper.this.handler.removeCallbacks(AppFrontBackHelper.this.check);
            }
            if (wasBackground) {
                if (AppFrontBackHelper.this.mListener != null) {
                    AppFrontBackHelper.this.mListener.onFront();
                    return;
                }
                return;
            }
            Log.i(AppFrontBackHelper.TAG, "still foreground");
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPaused(Activity activity) {
            AppFrontBackHelper.this.stoped = true;
            if (AppFrontBackHelper.this.handler != null) {
                if (AppFrontBackHelper.this.check != null) {
                    AppFrontBackHelper.this.handler.removeCallbacks(AppFrontBackHelper.this.check);
                }
                AppFrontBackHelper.this.handler.postDelayed(AppFrontBackHelper.this.check = new Runnable() { // from class: com.ding.rtc.monitor.AppFrontBackHelper.1.1
                    @Override // java.lang.Runnable
                    public void run() {
                        if (AppFrontBackHelper.this.foreground && AppFrontBackHelper.this.stoped) {
                            AppFrontBackHelper.this.foreground = false;
                            if (AppFrontBackHelper.this.mListener != null) {
                                AppFrontBackHelper.this.mListener.onBack();
                                return;
                            }
                            return;
                        }
                        Log.i(AppFrontBackHelper.TAG, "still foreground");
                    }
                }, 500L);
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

    public interface OnAppStatusListener {
        void onBack();

        void onFront();
    }

    public void bindApplication(Application application, final OnAppStatusListener listener) {
        if (application == null) {
            return;
        }
        this.mHandlerThread.start();
        this.handler = new Handler(this.mHandlerThread.getLooper());
        this.mListener = listener;
        application.registerActivityLifecycleCallbacks(this.mLifecycleCallback);
    }

    public void unBindApplication(Application application) {
        if (application != null) {
            application.unregisterActivityLifecycleCallbacks(this.mLifecycleCallback);
        }
        this.mHandlerThread.quit();
        this.mListener = null;
        this.handler = null;
    }

    public static boolean isBackground(Context context) {
        ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
        KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService("keyguard");
        List<ActivityManager.RunningAppProcessInfo> appProcesses = activityManager.getRunningAppProcesses();
        if (appProcesses == null) {
            return false;
        }
        for (ActivityManager.RunningAppProcessInfo appProcess : appProcesses) {
            if (TextUtils.equals(appProcess.processName, context.getPackageName())) {
                boolean isBackground = (appProcess.importance == 100 || appProcess.importance == 200) ? false : true;
                boolean isLockedState = keyguardManager.inKeyguardRestrictedInputMode();
                return isBackground || isLockedState;
            }
        }
        return false;
    }
}
