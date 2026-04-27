package com.blankj.utilcode.util;

import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.text.TextUtils;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import androidx.core.content.FileProvider;
import androidx.fragment.app.FragmentActivity;
import com.google.android.exoplayer2.C;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;

/* JADX INFO: loaded from: classes.dex */
public final class Utils {
    private static Application sApplication;
    private static final ActivityLifecycleImpl ACTIVITY_LIFECYCLE = new ActivityLifecycleImpl();
    private static final ExecutorService UTIL_POOL = ThreadUtils.getCachedPool();
    private static final Handler UTIL_HANDLER = new Handler(Looper.getMainLooper());

    public interface Callback<T> {
        void onCall(T t);
    }

    public interface Func1<Ret, Par> {
        Ret call(Par par);
    }

    public interface OnActivityDestroyedListener {
        void onActivityDestroyed(Activity activity);
    }

    public interface OnAppStatusChangedListener {
        void onBackground(Activity activity);

        void onForeground(Activity activity);
    }

    private Utils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    public static void init(Context context) {
        if (context == null) {
            init(getApplicationByReflect());
        } else {
            init((Application) context.getApplicationContext());
        }
    }

    public static void init(Application app) {
        if (sApplication == null) {
            if (app == null) {
                sApplication = getApplicationByReflect();
            } else {
                sApplication = app;
            }
            sApplication.registerActivityLifecycleCallbacks(ACTIVITY_LIFECYCLE);
            UTIL_POOL.execute(new Runnable() { // from class: com.blankj.utilcode.util.Utils.1
                @Override // java.lang.Runnable
                public void run() {
                    AdaptScreenUtils.preLoad();
                }
            });
            return;
        }
        if (app != null && app.getClass() != sApplication.getClass()) {
            sApplication.unregisterActivityLifecycleCallbacks(ACTIVITY_LIFECYCLE);
            ACTIVITY_LIFECYCLE.mActivityList.clear();
            sApplication = app;
            app.registerActivityLifecycleCallbacks(ACTIVITY_LIFECYCLE);
        }
    }

    public static Application getApp() {
        Application application = sApplication;
        if (application != null) {
            return application;
        }
        Application app = getApplicationByReflect();
        init(app);
        return app;
    }

    static ActivityLifecycleImpl getActivityLifecycle() {
        return ACTIVITY_LIFECYCLE;
    }

    static LinkedList<Activity> getActivityList() {
        return ACTIVITY_LIFECYCLE.mActivityList;
    }

    static Context getTopActivityOrApp() {
        if (isAppForeground()) {
            Activity topActivity = ACTIVITY_LIFECYCLE.getTopActivity();
            return topActivity == null ? getApp() : topActivity;
        }
        return getApp();
    }

    static boolean isAppForeground() {
        List<ActivityManager.RunningAppProcessInfo> info;
        ActivityManager am = (ActivityManager) getApp().getSystemService("activity");
        if (am == null || (info = am.getRunningAppProcesses()) == null || info.size() == 0) {
            return false;
        }
        for (ActivityManager.RunningAppProcessInfo aInfo : info) {
            if (aInfo.importance == 100 && aInfo.processName.equals(getApp().getPackageName())) {
                return true;
            }
        }
        return false;
    }

    static <T> Task<T> doAsync(Task<T> task) {
        UTIL_POOL.execute(task);
        return task;
    }

    public static void runOnUiThread(Runnable runnable) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            runnable.run();
        } else {
            UTIL_HANDLER.post(runnable);
        }
    }

    public static void runOnUiThreadDelayed(Runnable runnable, long delayMillis) {
        UTIL_HANDLER.postDelayed(runnable, delayMillis);
    }

    static String getCurrentProcessName() {
        String name = getCurrentProcessNameByFile();
        if (!TextUtils.isEmpty(name)) {
            return name;
        }
        String name2 = getCurrentProcessNameByAms();
        return !TextUtils.isEmpty(name2) ? name2 : getCurrentProcessNameByReflect();
    }

    static void fixSoftInputLeaks(Window window) {
        InputMethodManager imm = (InputMethodManager) getApp().getSystemService("input_method");
        if (imm == null) {
            return;
        }
        String[] leakViews = {"mLastSrvView", "mCurRootView", "mServedView", "mNextServedView"};
        for (String leakView : leakViews) {
            try {
                Field leakViewField = InputMethodManager.class.getDeclaredField(leakView);
                if (!leakViewField.isAccessible()) {
                    leakViewField.setAccessible(true);
                }
                Object obj = leakViewField.get(imm);
                if (obj instanceof View) {
                    View view = (View) obj;
                    if (view.getRootView() == window.getDecorView().getRootView()) {
                        leakViewField.set(imm, null);
                    }
                }
            } catch (Throwable th) {
            }
        }
    }

    static SPUtils getSpUtils4Utils() {
        return SPUtils.getInstance("Utils");
    }

    private static String getCurrentProcessNameByFile() {
        try {
            File file = new File("/proc/" + Process.myPid() + "/cmdline");
            BufferedReader mBufferedReader = new BufferedReader(new FileReader(file));
            String processName = mBufferedReader.readLine().trim();
            mBufferedReader.close();
            return processName;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    private static String getCurrentProcessNameByAms() {
        List<ActivityManager.RunningAppProcessInfo> info;
        ActivityManager am = (ActivityManager) getApp().getSystemService("activity");
        if (am == null || (info = am.getRunningAppProcesses()) == null || info.size() == 0) {
            return "";
        }
        int pid = Process.myPid();
        for (ActivityManager.RunningAppProcessInfo aInfo : info) {
            if (aInfo.pid == pid && aInfo.processName != null) {
                return aInfo.processName;
            }
        }
        return "";
    }

    private static String getCurrentProcessNameByReflect() {
        try {
            Application app = getApp();
            Field loadedApkField = app.getClass().getField("mLoadedApk");
            loadedApkField.setAccessible(true);
            Object loadedApk = loadedApkField.get(app);
            Field activityThreadField = loadedApk.getClass().getDeclaredField("mActivityThread");
            activityThreadField.setAccessible(true);
            Object activityThread = activityThreadField.get(loadedApk);
            Method getProcessName = activityThread.getClass().getDeclaredMethod("getProcessName", new Class[0]);
            String processName = (String) getProcessName.invoke(activityThread, new Object[0]);
            return processName;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    private static Application getApplicationByReflect() {
        try {
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Object thread = activityThread.getMethod("currentActivityThread", new Class[0]).invoke(null, new Object[0]);
            Object app = activityThread.getMethod("getApplication", new Class[0]).invoke(thread, new Object[0]);
            if (app == null) {
                throw new NullPointerException("u should init first");
            }
            return (Application) app;
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            throw new NullPointerException("u should init first");
        } catch (IllegalAccessException e2) {
            e2.printStackTrace();
            throw new NullPointerException("u should init first");
        } catch (NoSuchMethodException e3) {
            e3.printStackTrace();
            throw new NullPointerException("u should init first");
        } catch (InvocationTargetException e4) {
            e4.printStackTrace();
            throw new NullPointerException("u should init first");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void setAnimatorsEnabled() {
        if (Build.VERSION.SDK_INT >= 26 && ValueAnimator.areAnimatorsEnabled()) {
            return;
        }
        try {
            Field sDurationScaleField = ValueAnimator.class.getDeclaredField("sDurationScale");
            sDurationScaleField.setAccessible(true);
            float sDurationScale = ((Float) sDurationScaleField.get(null)).floatValue();
            if (sDurationScale == 0.0f) {
                sDurationScaleField.set(null, Float.valueOf(1.0f));
                Log.i("Utils", "setAnimatorsEnabled: Animators are enabled now!");
            }
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e2) {
            e2.printStackTrace();
        }
    }

    public static final class TransActivity extends FragmentActivity {
        private static final Map<TransActivity, TransActivityDelegate> CALLBACK_MAP = new HashMap();
        private static TransActivityDelegate sDelegate;

        public static void start(Func1<Void, Intent> consumer, TransActivityDelegate delegate) {
            if (delegate == null) {
                return;
            }
            Intent starter = new Intent(Utils.getApp(), (Class<?>) TransActivity.class);
            starter.addFlags(C.ENCODING_PCM_MU_LAW);
            if (consumer != null) {
                consumer.call(starter);
            }
            Utils.getApp().startActivity(starter);
            sDelegate = delegate;
        }

        @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
        protected void onCreate(Bundle savedInstanceState) {
            overridePendingTransition(0, 0);
            TransActivityDelegate transActivityDelegate = sDelegate;
            if (transActivityDelegate == null) {
                super.onCreate(savedInstanceState);
                finish();
                return;
            }
            CALLBACK_MAP.put(this, transActivityDelegate);
            sDelegate.onCreateBefore(this, savedInstanceState);
            super.onCreate(savedInstanceState);
            sDelegate.onCreated(this, savedInstanceState);
            sDelegate = null;
        }

        @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
        protected void onStart() {
            super.onStart();
            TransActivityDelegate callback = CALLBACK_MAP.get(this);
            if (callback == null) {
                return;
            }
            callback.onStarted(this);
        }

        @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
        protected void onResume() {
            super.onResume();
            TransActivityDelegate callback = CALLBACK_MAP.get(this);
            if (callback == null) {
                return;
            }
            callback.onResumed(this);
        }

        @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
        protected void onPause() {
            overridePendingTransition(0, 0);
            super.onPause();
            TransActivityDelegate callback = CALLBACK_MAP.get(this);
            if (callback == null) {
                return;
            }
            callback.onPaused(this);
        }

        @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
        protected void onStop() {
            super.onStop();
            TransActivityDelegate callback = CALLBACK_MAP.get(this);
            if (callback == null) {
                return;
            }
            callback.onStopped(this);
        }

        @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
        protected void onSaveInstanceState(Bundle outState) {
            super.onSaveInstanceState(outState);
            TransActivityDelegate callback = CALLBACK_MAP.get(this);
            if (callback == null) {
                return;
            }
            callback.onSaveInstanceState(this, outState);
        }

        @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
        protected void onDestroy() {
            super.onDestroy();
            TransActivityDelegate callback = CALLBACK_MAP.get(this);
            if (callback == null) {
                return;
            }
            callback.onDestroy(this);
            CALLBACK_MAP.remove(this);
        }

        @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
        public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
            super.onRequestPermissionsResult(requestCode, permissions, grantResults);
            TransActivityDelegate callback = CALLBACK_MAP.get(this);
            if (callback == null) {
                return;
            }
            callback.onRequestPermissionsResult(this, requestCode, permissions, grantResults);
        }

        @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
        protected void onActivityResult(int requestCode, int resultCode, Intent data) {
            super.onActivityResult(requestCode, resultCode, data);
            TransActivityDelegate callback = CALLBACK_MAP.get(this);
            if (callback == null) {
                return;
            }
            callback.onActivityResult(this, requestCode, resultCode, data);
        }

        @Override // android.app.Activity, android.view.Window.Callback
        public boolean dispatchTouchEvent(MotionEvent ev) {
            TransActivityDelegate callback = CALLBACK_MAP.get(this);
            if (callback == null) {
                return super.dispatchTouchEvent(ev);
            }
            if (callback.dispatchTouchEvent(this, ev)) {
                return true;
            }
            return super.dispatchTouchEvent(ev);
        }

        public static abstract class TransActivityDelegate {
            public void onCreateBefore(Activity activity, Bundle savedInstanceState) {
            }

            public void onCreated(Activity activity, Bundle savedInstanceState) {
            }

            public void onStarted(Activity activity) {
            }

            public void onDestroy(Activity activity) {
            }

            public void onResumed(Activity activity) {
            }

            public void onPaused(Activity activity) {
            }

            public void onStopped(Activity activity) {
            }

            public void onSaveInstanceState(Activity activity, Bundle outState) {
            }

            public void onRequestPermissionsResult(Activity activity, int requestCode, String[] permissions, int[] grantResults) {
            }

            public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent data) {
            }

            public boolean dispatchTouchEvent(Activity activity, MotionEvent ev) {
                return false;
            }
        }
    }

    static class ActivityLifecycleImpl implements Application.ActivityLifecycleCallbacks {
        final LinkedList<Activity> mActivityList = new LinkedList<>();
        final List<OnAppStatusChangedListener> mStatusListeners = new ArrayList();
        final Map<Activity, List<OnActivityDestroyedListener>> mDestroyedListenerMap = new HashMap();
        private int mForegroundCount = 0;
        private int mConfigCount = 0;
        private boolean mIsBackground = false;

        ActivityLifecycleImpl() {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
            LanguageUtils.applyLanguage(activity);
            Utils.setAnimatorsEnabled();
            setTopActivity(activity);
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStarted(Activity activity) {
            if (!this.mIsBackground) {
                setTopActivity(activity);
            }
            int i = this.mConfigCount;
            if (i < 0) {
                this.mConfigCount = i + 1;
            } else {
                this.mForegroundCount++;
            }
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityResumed(Activity activity) {
            setTopActivity(activity);
            if (this.mIsBackground) {
                this.mIsBackground = false;
                postStatus(activity, true);
            }
            processHideSoftInputOnActivityDestroy(activity, false);
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPaused(Activity activity) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStopped(Activity activity) {
            if (activity.isChangingConfigurations()) {
                this.mConfigCount--;
            } else {
                int i = this.mForegroundCount - 1;
                this.mForegroundCount = i;
                if (i <= 0) {
                    this.mIsBackground = true;
                    postStatus(activity, false);
                }
            }
            processHideSoftInputOnActivityDestroy(activity, true);
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityDestroyed(Activity activity) {
            this.mActivityList.remove(activity);
            consumeOnActivityDestroyedListener(activity);
            Utils.fixSoftInputLeaks(activity.getWindow());
        }

        Activity getTopActivity() {
            if (!this.mActivityList.isEmpty()) {
                for (int i = this.mActivityList.size() - 1; i >= 0; i--) {
                    Activity activity = this.mActivityList.get(i);
                    if (activity != null && !activity.isFinishing() && (Build.VERSION.SDK_INT < 17 || !activity.isDestroyed())) {
                        return activity;
                    }
                }
            }
            Activity topActivityByReflect = getTopActivityByReflect();
            if (topActivityByReflect != null) {
                setTopActivity(topActivityByReflect);
            }
            return topActivityByReflect;
        }

        void addOnAppStatusChangedListener(OnAppStatusChangedListener listener) {
            this.mStatusListeners.add(listener);
        }

        void removeOnAppStatusChangedListener(OnAppStatusChangedListener listener) {
            this.mStatusListeners.remove(listener);
        }

        void removeOnActivityDestroyedListener(Activity activity) {
            if (activity == null) {
                return;
            }
            this.mDestroyedListenerMap.remove(activity);
        }

        void addOnActivityDestroyedListener(Activity activity, OnActivityDestroyedListener listener) {
            if (activity == null || listener == null) {
                return;
            }
            List<OnActivityDestroyedListener> listeners = this.mDestroyedListenerMap.get(activity);
            if (listeners == null) {
                listeners = new CopyOnWriteArrayList();
                this.mDestroyedListenerMap.put(activity, listeners);
            } else if (listeners.contains(listener)) {
                return;
            }
            listeners.add(listener);
        }

        private void processHideSoftInputOnActivityDestroy(final Activity activity, boolean isSave) {
            if (!isSave) {
                final Object tag = activity.getWindow().getDecorView().getTag(-123);
                if (tag instanceof Integer) {
                    Utils.runOnUiThreadDelayed(new Runnable() { // from class: com.blankj.utilcode.util.Utils.ActivityLifecycleImpl.1
                        @Override // java.lang.Runnable
                        public void run() {
                            Window window = activity.getWindow();
                            if (window != null) {
                                window.setSoftInputMode(((Integer) tag).intValue());
                            }
                        }
                    }, 100L);
                    return;
                }
                return;
            }
            WindowManager.LayoutParams attrs = activity.getWindow().getAttributes();
            int softInputMode = attrs.softInputMode;
            activity.getWindow().getDecorView().setTag(-123, Integer.valueOf(softInputMode));
            activity.getWindow().setSoftInputMode(3);
        }

        private void postStatus(Activity activity, boolean isForeground) {
            if (this.mStatusListeners.isEmpty()) {
                return;
            }
            for (OnAppStatusChangedListener statusListener : this.mStatusListeners) {
                if (isForeground) {
                    statusListener.onForeground(activity);
                } else {
                    statusListener.onBackground(activity);
                }
            }
        }

        private void setTopActivity(Activity activity) {
            if (this.mActivityList.contains(activity)) {
                if (!this.mActivityList.getLast().equals(activity)) {
                    this.mActivityList.remove(activity);
                    this.mActivityList.addLast(activity);
                    return;
                }
                return;
            }
            this.mActivityList.addLast(activity);
        }

        private void consumeOnActivityDestroyedListener(Activity activity) {
            Iterator<Map.Entry<Activity, List<OnActivityDestroyedListener>>> iterator = this.mDestroyedListenerMap.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<Activity, List<OnActivityDestroyedListener>> entry = iterator.next();
                if (entry.getKey() == activity) {
                    List<OnActivityDestroyedListener> value = entry.getValue();
                    for (OnActivityDestroyedListener listener : value) {
                        listener.onActivityDestroyed(activity);
                    }
                    iterator.remove();
                }
            }
        }

        private Activity getTopActivityByReflect() {
            try {
                Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
                Object currentActivityThreadMethod = activityThreadClass.getMethod("currentActivityThread", new Class[0]).invoke(null, new Object[0]);
                Field mActivityListField = activityThreadClass.getDeclaredField("mActivityList");
                mActivityListField.setAccessible(true);
                Map activities = (Map) mActivityListField.get(currentActivityThreadMethod);
                if (activities == null) {
                    return null;
                }
                for (Object activityRecord : activities.values()) {
                    Class<?> cls = activityRecord.getClass();
                    Field pausedField = cls.getDeclaredField("paused");
                    pausedField.setAccessible(true);
                    if (!pausedField.getBoolean(activityRecord)) {
                        Field activityField = cls.getDeclaredField("activity");
                        activityField.setAccessible(true);
                        return (Activity) activityField.get(activityRecord);
                    }
                }
            } catch (Exception e) {
                Log.e("Utils", e.getMessage());
            }
            return null;
        }
    }

    public static final class FileProvider4UtilCode extends FileProvider {
        @Override // androidx.core.content.FileProvider, android.content.ContentProvider
        public boolean onCreate() {
            Utils.init(getContext());
            try {
                Class.forName("com.blankj.utildebug.DebugUtils");
                return true;
            } catch (ClassNotFoundException e) {
                return true;
            }
        }
    }

    public static abstract class Task<Result> implements Runnable {
        private static final int CANCELLED = 2;
        private static final int COMPLETING = 1;
        private static final int EXCEPTIONAL = 3;
        private static final int NEW = 0;
        private Callback<Result> mCallback;
        private volatile int state = 0;

        abstract Result doInBackground();

        public Task(Callback<Result> callback) {
            this.mCallback = callback;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                final Result t = doInBackground();
                if (this.state != 0) {
                    return;
                }
                this.state = 1;
                Utils.UTIL_HANDLER.post(new Runnable() { // from class: com.blankj.utilcode.util.Utils.Task.1
                    @Override // java.lang.Runnable
                    public void run() {
                        Task.this.mCallback.onCall(t);
                    }
                });
            } catch (Throwable th) {
                if (this.state != 0) {
                    return;
                }
                this.state = 3;
            }
        }

        public void cancel() {
            this.state = 2;
        }

        public boolean isDone() {
            return this.state != 0;
        }

        public boolean isCanceled() {
            return this.state == 2;
        }
    }
}
