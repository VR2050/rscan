package com.facebook.react.uimanager;

import android.content.ComponentCallbacks2;
import android.content.res.Configuration;
import com.facebook.react.bridge.UiThreadUtil;
import d1.AbstractC0508d;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public final class U0 implements ComponentCallbacks2 {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Map f7519b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final V0 f7520c;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ List f7521b;

        a(List list) {
            this.f7521b = list;
        }

        @Override // java.lang.Runnable
        public void run() {
            Iterator it = this.f7521b.iterator();
            while (it.hasNext()) {
                ((ViewManager) it.next()).trimMemory();
            }
        }
    }

    public U0(V0 v02) {
        this.f7519b = AbstractC0508d.b();
        this.f7520c = v02;
    }

    private ViewManager d(String str) {
        ViewManager viewManagerA = this.f7520c.a(str);
        if (viewManagerA != null) {
            this.f7519b.put(str, viewManagerA);
        }
        return viewManagerA;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void g(List list) {
        Iterator it = list.iterator();
        while (it.hasNext()) {
            ((ViewManager) it.next()).invalidate();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void h(List list, int i3) {
        Iterator it = list.iterator();
        while (it.hasNext()) {
            ((ViewManager) it.next()).onSurfaceStopped(i3);
        }
    }

    public synchronized ViewManager c(String str) {
        try {
            ViewManager viewManager = (ViewManager) this.f7519b.get(str);
            if (viewManager != null) {
                return viewManager;
            }
            String str2 = "RCT" + str;
            ViewManager viewManager2 = (ViewManager) this.f7519b.get(str2);
            if (viewManager2 != null) {
                return viewManager2;
            }
            if (this.f7520c == null) {
                throw new P("No ViewManager found for class " + str);
            }
            ViewManager viewManagerD = d(str);
            if (viewManagerD != null) {
                return viewManagerD;
            }
            ViewManager viewManagerD2 = d(str2);
            if (viewManagerD2 != null) {
                return viewManagerD2;
            }
            throw new P("ViewManagerResolver returned null for either " + str + " or " + str2 + ", existing names are: " + this.f7520c.b());
        } catch (Throwable th) {
            throw th;
        }
    }

    synchronized ViewManager e(String str) {
        ViewManager viewManager = (ViewManager) this.f7519b.get(str);
        if (viewManager != null) {
            return viewManager;
        }
        if (this.f7520c == null) {
            return null;
        }
        return d(str);
    }

    public void f() {
        final ArrayList arrayList;
        synchronized (this) {
            arrayList = new ArrayList(this.f7519b.values());
        }
        Runnable runnable = new Runnable() { // from class: com.facebook.react.uimanager.S0
            @Override // java.lang.Runnable
            public final void run() {
                U0.g(arrayList);
            }
        };
        if (UiThreadUtil.isOnUiThread()) {
            runnable.run();
        } else {
            UiThreadUtil.runOnUiThread(runnable);
        }
    }

    public void i(final int i3) {
        final ArrayList arrayList;
        synchronized (this) {
            arrayList = new ArrayList(this.f7519b.values());
        }
        Runnable runnable = new Runnable() { // from class: com.facebook.react.uimanager.T0
            @Override // java.lang.Runnable
            public final void run() {
                U0.h(arrayList, i3);
            }
        };
        if (UiThreadUtil.isOnUiThread()) {
            runnable.run();
        } else {
            UiThreadUtil.runOnUiThread(runnable);
        }
    }

    @Override // android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
    }

    @Override // android.content.ComponentCallbacks
    public void onLowMemory() {
        onTrimMemory(0);
    }

    @Override // android.content.ComponentCallbacks2
    public void onTrimMemory(int i3) {
        ArrayList arrayList;
        synchronized (this) {
            arrayList = new ArrayList(this.f7519b.values());
        }
        a aVar = new a(arrayList);
        if (UiThreadUtil.isOnUiThread()) {
            aVar.run();
        } else {
            UiThreadUtil.runOnUiThread(aVar);
        }
    }

    public U0(List list) {
        HashMap mapB = AbstractC0508d.b();
        Iterator it = list.iterator();
        while (it.hasNext()) {
            ViewManager viewManager = (ViewManager) it.next();
            mapB.put(viewManager.getName(), viewManager);
        }
        this.f7519b = mapB;
        this.f7520c = null;
    }
}
