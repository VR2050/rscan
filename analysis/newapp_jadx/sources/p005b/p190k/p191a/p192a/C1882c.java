package p005b.p190k.p191a.p192a;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import com.github.anzewei.parallaxbacklayout.R$id;
import com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout;
import p005b.p190k.p191a.p192a.p193e.C1884a;
import p005b.p190k.p191a.p192a.p193e.C1886c;
import p005b.p190k.p191a.p192a.p193e.C1887d;

/* renamed from: b.k.a.a.c */
/* loaded from: classes.dex */
public class C1882c implements Application.ActivityLifecycleCallbacks {

    /* renamed from: c */
    public static C1882c f2913c;

    /* renamed from: e */
    public C1880a<Activity, c> f2914e = new C1880a<>();

    /* renamed from: b.k.a.a.c$b */
    public static class b implements ParallaxBackLayout.InterfaceC3254b {

        /* renamed from: a */
        public Activity f2915a;

        /* renamed from: b */
        public Activity f2916b;

        public b(Activity activity, a aVar) {
            this.f2915a = activity;
        }

        /* renamed from: a */
        public boolean m1214a() {
            C1880a<Activity, c> c1880a = C1882c.f2913c.f2914e;
            int indexOf = c1880a.f2896a.indexOf(this.f2915a);
            Activity activity = indexOf < 1 ? null : c1880a.f2896a.get(indexOf - 1);
            this.f2916b = activity;
            return activity != null;
        }
    }

    /* renamed from: b.k.a.a.c$c */
    public static class c {
    }

    /* renamed from: a */
    public static ParallaxBackLayout m1213a(Activity activity, boolean z) {
        View childAt = ((ViewGroup) activity.getWindow().getDecorView()).getChildAt(0);
        if (childAt instanceof ParallaxBackLayout) {
            return (ParallaxBackLayout) childAt;
        }
        int i2 = R$id.pllayout;
        View findViewById = activity.findViewById(i2);
        if (findViewById instanceof ParallaxBackLayout) {
            return (ParallaxBackLayout) findViewById;
        }
        if (!z) {
            return null;
        }
        ParallaxBackLayout parallaxBackLayout = new ParallaxBackLayout(activity);
        parallaxBackLayout.setId(i2);
        parallaxBackLayout.m4018b(activity);
        parallaxBackLayout.setBackgroundView(new b(activity, null));
        return parallaxBackLayout;
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityCreated(Activity activity, Bundle bundle) {
        InterfaceC1881b interfaceC1881b;
        c cVar = new c();
        C1880a<Activity, c> c1880a = this.f2914e;
        c1880a.f2896a.add(activity);
        c1880a.f2897b.put(activity, cVar);
        Class<?> cls = activity.getClass();
        while (true) {
            if (!Activity.class.isAssignableFrom(cls)) {
                interfaceC1881b = null;
                break;
            }
            interfaceC1881b = (InterfaceC1881b) cls.getAnnotation(InterfaceC1881b.class);
            if (interfaceC1881b != null) {
                break;
            } else {
                cls = cls.getSuperclass();
            }
        }
        if (this.f2914e.f2896a.size() <= 0 || interfaceC1881b == null) {
            return;
        }
        ParallaxBackLayout m1213a = m1213a(activity, true);
        m1213a.setEnableGesture(true);
        m1213a.setEdgeFlag(interfaceC1881b.edge().f2903i);
        m1213a.setEdgeMode(interfaceC1881b.edgeMode().f2907g);
        int i2 = interfaceC1881b.layout().f2912h;
        m1213a.f9199o = i2;
        if (i2 == -1) {
            m1213a.f9195k = null;
            return;
        }
        if (i2 == 0) {
            m1213a.f9195k = new C1884a();
        } else if (i2 == 1) {
            m1213a.f9195k = new C1886c();
        } else {
            if (i2 != 2) {
                return;
            }
            m1213a.f9195k = new C1887d();
        }
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityDestroyed(Activity activity) {
        C1880a<Activity, c> c1880a = this.f2914e;
        c1880a.f2896a.remove(activity);
        c1880a.f2897b.remove(activity);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPaused(Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityResumed(Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivitySaveInstanceState(Activity activity, Bundle bundle) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStarted(Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStopped(Activity activity) {
    }
}
