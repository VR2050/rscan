package androidx.core.app;

import android.app.Activity;
import android.app.Application;
import android.content.res.Configuration;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
abstract class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected static final Class f4225a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected static final Field f4226b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected static final Field f4227c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected static final Method f4228d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    protected static final Method f4229e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    protected static final Method f4230f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final Handler f4231g = new Handler(Looper.getMainLooper());

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ d f4232b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Object f4233c;

        a(d dVar, Object obj) {
            this.f4232b = dVar;
            this.f4233c = obj;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f4232b.f4238a = this.f4233c;
        }
    }

    class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Application f4234b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ d f4235c;

        b(Application application, d dVar) {
            this.f4234b = application;
            this.f4235c = dVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f4234b.unregisterActivityLifecycleCallbacks(this.f4235c);
        }
    }

    /* JADX INFO: renamed from: androidx.core.app.c$c, reason: collision with other inner class name */
    class RunnableC0055c implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Object f4236b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Object f4237c;

        RunnableC0055c(Object obj, Object obj2) {
            this.f4236b = obj;
            this.f4237c = obj2;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                Method method = c.f4228d;
                if (method != null) {
                    method.invoke(this.f4236b, this.f4237c, Boolean.FALSE, "AppCompat recreation");
                } else {
                    c.f4229e.invoke(this.f4236b, this.f4237c, Boolean.FALSE);
                }
            } catch (RuntimeException e3) {
                if (e3.getClass() == RuntimeException.class && e3.getMessage() != null && e3.getMessage().startsWith("Unable to stop")) {
                    throw e3;
                }
            } catch (Throwable th) {
                Log.e("ActivityRecreator", "Exception while invoking performStopActivity", th);
            }
        }
    }

    private static final class d implements Application.ActivityLifecycleCallbacks {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        Object f4238a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private Activity f4239b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f4240c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f4241d = false;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f4242e = false;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f4243f = false;

        d(Activity activity) {
            this.f4239b = activity;
            this.f4240c = activity.hashCode();
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityCreated(Activity activity, Bundle bundle) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityDestroyed(Activity activity) {
            if (this.f4239b == activity) {
                this.f4239b = null;
                this.f4242e = true;
            }
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPaused(Activity activity) {
            if (!this.f4242e || this.f4243f || this.f4241d || !c.h(this.f4238a, this.f4240c, activity)) {
                return;
            }
            this.f4243f = true;
            this.f4238a = null;
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityResumed(Activity activity) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStarted(Activity activity) {
            if (this.f4239b == activity) {
                this.f4241d = true;
            }
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStopped(Activity activity) {
        }
    }

    static {
        Class clsA = a();
        f4225a = clsA;
        f4226b = b();
        f4227c = f();
        f4228d = d(clsA);
        f4229e = c(clsA);
        f4230f = e(clsA);
    }

    private static Class a() {
        try {
            return Class.forName("android.app.ActivityThread");
        } catch (Throwable unused) {
            return null;
        }
    }

    private static Field b() {
        try {
            Field declaredField = Activity.class.getDeclaredField("mMainThread");
            declaredField.setAccessible(true);
            return declaredField;
        } catch (Throwable unused) {
            return null;
        }
    }

    private static Method c(Class cls) {
        if (cls == null) {
            return null;
        }
        try {
            Method declaredMethod = cls.getDeclaredMethod("performStopActivity", IBinder.class, Boolean.TYPE);
            declaredMethod.setAccessible(true);
            return declaredMethod;
        } catch (Throwable unused) {
            return null;
        }
    }

    private static Method d(Class cls) {
        if (cls == null) {
            return null;
        }
        try {
            Method declaredMethod = cls.getDeclaredMethod("performStopActivity", IBinder.class, Boolean.TYPE, String.class);
            declaredMethod.setAccessible(true);
            return declaredMethod;
        } catch (Throwable unused) {
            return null;
        }
    }

    private static Method e(Class cls) {
        if (g() && cls != null) {
            try {
                Class cls2 = Integer.TYPE;
                Class cls3 = Boolean.TYPE;
                Method declaredMethod = cls.getDeclaredMethod("requestRelaunchActivity", IBinder.class, List.class, List.class, cls2, cls3, Configuration.class, Configuration.class, cls3, cls3);
                declaredMethod.setAccessible(true);
                return declaredMethod;
            } catch (Throwable unused) {
            }
        }
        return null;
    }

    private static Field f() {
        try {
            Field declaredField = Activity.class.getDeclaredField("mToken");
            declaredField.setAccessible(true);
            return declaredField;
        } catch (Throwable unused) {
            return null;
        }
    }

    private static boolean g() {
        int i3 = Build.VERSION.SDK_INT;
        return i3 == 26 || i3 == 27;
    }

    protected static boolean h(Object obj, int i3, Activity activity) {
        try {
            Object obj2 = f4227c.get(activity);
            if (obj2 == obj && activity.hashCode() == i3) {
                f4231g.postAtFrontOfQueue(new RunnableC0055c(f4226b.get(activity), obj2));
                return true;
            }
            return false;
        } catch (Throwable th) {
            Log.e("ActivityRecreator", "Exception while fetching field values", th);
            return false;
        }
    }

    static boolean i(Activity activity) {
        Object obj;
        if (Build.VERSION.SDK_INT >= 28) {
            activity.recreate();
            return true;
        }
        if (g() && f4230f == null) {
            return false;
        }
        if (f4229e == null && f4228d == null) {
            return false;
        }
        try {
            Object obj2 = f4227c.get(activity);
            if (obj2 == null || (obj = f4226b.get(activity)) == null) {
                return false;
            }
            Application application = activity.getApplication();
            d dVar = new d(activity);
            application.registerActivityLifecycleCallbacks(dVar);
            Handler handler = f4231g;
            handler.post(new a(dVar, obj2));
            try {
                if (g()) {
                    Method method = f4230f;
                    Boolean bool = Boolean.FALSE;
                    method.invoke(obj, obj2, null, null, 0, bool, null, null, bool, bool);
                } else {
                    activity.recreate();
                }
                handler.post(new b(application, dVar));
                return true;
            } catch (Throwable th) {
                f4231g.post(new b(application, dVar));
                throw th;
            }
        } catch (Throwable unused) {
            return false;
        }
    }
}
