package p005b.p139f.p140a.p142b;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.inputmethod.InputMethodManager;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.Lifecycle;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.f.a.b.s */
/* loaded from: classes.dex */
public final class C1549s implements Application.ActivityLifecycleCallbacks {

    /* renamed from: c */
    public static final C1549s f1795c = new C1549s();

    /* renamed from: e */
    public static final Activity f1796e = new Activity();

    /* renamed from: f */
    public final LinkedList<Activity> f1797f = new LinkedList<>();

    /* renamed from: g */
    public final List<InterfaceC1546p> f1798g = new CopyOnWriteArrayList();

    /* renamed from: h */
    public final Map<Activity, List<C1545o>> f1799h = new ConcurrentHashMap();

    /* renamed from: i */
    public int f1800i = 0;

    /* renamed from: j */
    public int f1801j = 0;

    /* renamed from: k */
    public boolean f1802k = false;

    /* renamed from: b.f.a.b.s$a */
    public class a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ Activity f1803c;

        /* renamed from: e */
        public final /* synthetic */ Object f1804e;

        public a(C1549s c1549s, Activity activity, Object obj) {
            this.f1803c = activity;
            this.f1804e = obj;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                Window window = this.f1803c.getWindow();
                if (window != null) {
                    window.setSoftInputMode(((Integer) this.f1804e).intValue());
                }
            } catch (Exception unused) {
            }
        }
    }

    /* renamed from: a */
    public final void m718a(Activity activity, Lifecycle.Event event) {
        m719b(activity, event, this.f1799h.get(activity));
        m719b(activity, event, this.f1799h.get(f1796e));
    }

    public void addOnAppStatusChangedListener(InterfaceC1546p interfaceC1546p) {
        this.f1798g.add(interfaceC1546p);
    }

    /* renamed from: b */
    public final void m719b(Activity activity, Lifecycle.Event event, List<C1545o> list) {
        if (list == null) {
            return;
        }
        for (C1545o c1545o : list) {
            Objects.requireNonNull(c1545o);
            if (event.equals(Lifecycle.Event.ON_CREATE)) {
                c1545o.mo715a(activity);
            } else if (!event.equals(Lifecycle.Event.ON_START) && !event.equals(Lifecycle.Event.ON_RESUME) && !event.equals(Lifecycle.Event.ON_PAUSE) && !event.equals(Lifecycle.Event.ON_STOP)) {
                event.equals(Lifecycle.Event.ON_DESTROY);
            }
        }
        if (event.equals(Lifecycle.Event.ON_DESTROY)) {
            this.f1799h.remove(activity);
        }
    }

    /* renamed from: c */
    public final Object m720c() {
        Object obj;
        try {
            Field declaredField = Class.forName("android.app.ActivityThread").getDeclaredField("sCurrentActivityThread");
            declaredField.setAccessible(true);
            obj = declaredField.get(null);
        } catch (Exception e2) {
            e2.getMessage();
            obj = null;
        }
        if (obj != null) {
            return obj;
        }
        try {
            return Class.forName("android.app.ActivityThread").getMethod("currentActivityThread", new Class[0]).invoke(null, new Object[0]);
        } catch (Exception e3) {
            e3.getMessage();
            return null;
        }
    }

    /* renamed from: d */
    public final void m721d(Activity activity, boolean z) {
        if (this.f1798g.isEmpty()) {
            return;
        }
        for (InterfaceC1546p interfaceC1546p : this.f1798g) {
            if (z) {
                interfaceC1546p.m716a(activity);
            } else {
                interfaceC1546p.m717b(activity);
            }
        }
    }

    /* renamed from: e */
    public final void m722e(Activity activity, boolean z) {
        try {
            if (z) {
                Window window = activity.getWindow();
                window.getDecorView().setTag(-123, Integer.valueOf(window.getAttributes().softInputMode));
                window.setSoftInputMode(3);
            } else {
                Object tag = activity.getWindow().getDecorView().getTag(-123);
                if (!(tag instanceof Integer)) {
                    return;
                }
                C1540j.f1772a.postDelayed(new a(this, activity, tag), 100L);
            }
        } catch (Exception unused) {
        }
    }

    /* renamed from: f */
    public final void m723f(Activity activity) {
        if (!this.f1797f.contains(activity)) {
            this.f1797f.addFirst(activity);
        } else {
            if (this.f1797f.getFirst().equals(activity)) {
                return;
            }
            this.f1797f.remove(activity);
            this.f1797f.addFirst(activity);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0061, code lost:
    
        r2 = false;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x007e  */
    @Override // android.app.Application.ActivityLifecycleCallbacks
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onActivityCreated(@androidx.annotation.NonNull android.app.Activity r11, android.os.Bundle r12) {
        /*
            Method dump skipped, instructions count: 253
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p139f.p140a.p142b.C1549s.onActivityCreated(android.app.Activity, android.os.Bundle):void");
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityDestroyed(@NonNull Activity activity) {
        this.f1797f.remove(activity);
        Window window = activity.getWindow();
        InputMethodManager inputMethodManager = (InputMethodManager) C4195m.m4792Y().getSystemService("input_method");
        if (inputMethodManager != null) {
            String[] strArr = {"mLastSrvView", "mCurRootView", "mServedView", "mNextServedView"};
            for (int i2 = 0; i2 < 4; i2++) {
                try {
                    Field declaredField = InputMethodManager.class.getDeclaredField(strArr[i2]);
                    if (!declaredField.isAccessible()) {
                        declaredField.setAccessible(true);
                    }
                    Object obj = declaredField.get(inputMethodManager);
                    if ((obj instanceof View) && ((View) obj).getRootView() == window.getDecorView().getRootView()) {
                        declaredField.set(inputMethodManager, null);
                    }
                } catch (Throwable unused) {
                }
            }
        }
        m718a(activity, Lifecycle.Event.ON_DESTROY);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPaused(@NonNull Activity activity) {
        m718a(activity, Lifecycle.Event.ON_PAUSE);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPostCreated(@NonNull Activity activity, @Nullable Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPostDestroyed(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPostPaused(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPostResumed(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPostSaveInstanceState(@NonNull Activity activity, @NonNull Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPostStarted(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPostStopped(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPreCreated(@NonNull Activity activity, @Nullable Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPreDestroyed(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPrePaused(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPreResumed(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPreSaveInstanceState(@NonNull Activity activity, @NonNull Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPreStarted(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPreStopped(@NonNull Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityResumed(@NonNull Activity activity) {
        m723f(activity);
        if (this.f1802k) {
            this.f1802k = false;
            m721d(activity, true);
        }
        m722e(activity, false);
        m718a(activity, Lifecycle.Event.ON_RESUME);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivitySaveInstanceState(@NonNull Activity activity, @NonNull Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStarted(@NonNull Activity activity) {
        if (!this.f1802k) {
            m723f(activity);
        }
        int i2 = this.f1801j;
        if (i2 < 0) {
            this.f1801j = i2 + 1;
        } else {
            this.f1800i++;
        }
        m718a(activity, Lifecycle.Event.ON_START);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStopped(Activity activity) {
        if (activity.isChangingConfigurations()) {
            this.f1801j--;
        } else {
            int i2 = this.f1800i - 1;
            this.f1800i = i2;
            if (i2 <= 0) {
                this.f1802k = true;
                m721d(activity, false);
            }
        }
        m722e(activity, true);
        m718a(activity, Lifecycle.Event.ON_STOP);
    }

    public void removeOnAppStatusChangedListener(InterfaceC1546p interfaceC1546p) {
        this.f1798g.remove(interfaceC1546p);
    }
}
