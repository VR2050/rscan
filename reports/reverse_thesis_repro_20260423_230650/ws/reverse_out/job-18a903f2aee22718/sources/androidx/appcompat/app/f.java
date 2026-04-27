package androidx.appcompat.app;

import android.app.Activity;
import android.app.Dialog;
import android.app.LocaleManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.os.Build;
import android.os.Bundle;
import android.os.LocaleList;
import android.util.Log;
import android.view.MenuInflater;
import android.view.View;
import android.view.ViewGroup;
import android.window.OnBackInvokedDispatcher;
import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.Queue;
import java.util.concurrent.Executor;
import l.C0607b;

/* JADX INFO: loaded from: classes.dex */
public abstract class f {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    static c f3133b = new c(new d());

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static int f3134c = -100;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static androidx.core.os.c f3135d = null;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static androidx.core.os.c f3136e = null;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static Boolean f3137f = null;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static boolean f3138g = false;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final C0607b f3139h = new C0607b();

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final Object f3140i = new Object();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final Object f3141j = new Object();

    static class a {
        static LocaleList a(String str) {
            return LocaleList.forLanguageTags(str);
        }
    }

    static class b {
        static LocaleList a(Object obj) {
            return ((LocaleManager) obj).getApplicationLocales();
        }

        static void b(Object obj, LocaleList localeList) {
            ((LocaleManager) obj).setApplicationLocales(localeList);
        }
    }

    static class c implements Executor {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Object f3142b = new Object();

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final Queue f3143c = new ArrayDeque();

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final Executor f3144d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        Runnable f3145e;

        c(Executor executor) {
            this.f3144d = executor;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void c(Runnable runnable) {
            try {
                runnable.run();
            } finally {
                d();
            }
        }

        protected void d() {
            synchronized (this.f3142b) {
                try {
                    Runnable runnable = (Runnable) this.f3143c.poll();
                    this.f3145e = runnable;
                    if (runnable != null) {
                        this.f3144d.execute(runnable);
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        @Override // java.util.concurrent.Executor
        public void execute(final Runnable runnable) {
            synchronized (this.f3142b) {
                try {
                    this.f3143c.add(new Runnable() { // from class: androidx.appcompat.app.g
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f3146b.c(runnable);
                        }
                    });
                    if (this.f3145e == null) {
                        d();
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    static class d implements Executor {
        d() {
        }

        @Override // java.util.concurrent.Executor
        public void execute(Runnable runnable) {
            new Thread(runnable).start();
        }
    }

    f() {
    }

    static void G(f fVar) {
        synchronized (f3140i) {
            H(fVar);
        }
    }

    private static void H(f fVar) {
        synchronized (f3140i) {
            try {
                Iterator it = f3139h.iterator();
                while (it.hasNext()) {
                    f fVar2 = (f) ((WeakReference) it.next()).get();
                    if (fVar2 == fVar || fVar2 == null) {
                        it.remove();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static void M(int i3) {
        if (i3 != -1 && i3 != 0 && i3 != 1 && i3 != 2 && i3 != 3) {
            Log.d("AppCompatDelegate", "setDefaultNightMode() called with an unknown mode");
        } else if (f3134c != i3) {
            f3134c = i3;
            g();
        }
    }

    static void Q(Context context) {
        if (Build.VERSION.SDK_INT >= 33) {
            ComponentName componentName = new ComponentName(context, "androidx.appcompat.app.AppLocalesMetadataHolderService");
            if (context.getPackageManager().getComponentEnabledSetting(componentName) != 1) {
                if (m().e()) {
                    String strB = androidx.core.app.d.b(context);
                    Object systemService = context.getSystemService("locale");
                    if (systemService != null) {
                        b.b(systemService, a.a(strB));
                    }
                }
                context.getPackageManager().setComponentEnabledSetting(componentName, 1, 1);
            }
        }
    }

    static void R(final Context context) {
        if (w(context)) {
            if (Build.VERSION.SDK_INT >= 33) {
                if (f3138g) {
                    return;
                }
                f3133b.execute(new Runnable() { // from class: androidx.appcompat.app.e
                    @Override // java.lang.Runnable
                    public final void run() {
                        f.x(context);
                    }
                });
                return;
            }
            synchronized (f3141j) {
                try {
                    androidx.core.os.c cVar = f3135d;
                    if (cVar == null) {
                        if (f3136e == null) {
                            f3136e = androidx.core.os.c.b(androidx.core.app.d.b(context));
                        }
                        if (f3136e.e()) {
                        } else {
                            f3135d = f3136e;
                        }
                    } else if (!cVar.equals(f3136e)) {
                        androidx.core.os.c cVar2 = f3135d;
                        f3136e = cVar2;
                        androidx.core.app.d.a(context, cVar2.g());
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    static void d(f fVar) {
        synchronized (f3140i) {
            H(fVar);
            f3139h.add(new WeakReference(fVar));
        }
    }

    private static void g() {
        synchronized (f3140i) {
            try {
                Iterator it = f3139h.iterator();
                while (it.hasNext()) {
                    f fVar = (f) ((WeakReference) it.next()).get();
                    if (fVar != null) {
                        fVar.f();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static f j(Activity activity, androidx.appcompat.app.d dVar) {
        return new h(activity, dVar);
    }

    public static f k(Dialog dialog, androidx.appcompat.app.d dVar) {
        return new h(dialog, dVar);
    }

    public static androidx.core.os.c m() {
        if (Build.VERSION.SDK_INT >= 33) {
            Object objQ = q();
            if (objQ != null) {
                return androidx.core.os.c.h(b.a(objQ));
            }
        } else {
            androidx.core.os.c cVar = f3135d;
            if (cVar != null) {
                return cVar;
            }
        }
        return androidx.core.os.c.d();
    }

    public static int o() {
        return f3134c;
    }

    static Object q() {
        Context contextN;
        Iterator it = f3139h.iterator();
        while (it.hasNext()) {
            f fVar = (f) ((WeakReference) it.next()).get();
            if (fVar != null && (contextN = fVar.n()) != null) {
                return contextN.getSystemService("locale");
            }
        }
        return null;
    }

    static androidx.core.os.c s() {
        return f3135d;
    }

    static boolean w(Context context) {
        if (f3137f == null) {
            try {
                Bundle bundle = t.a(context).metaData;
                if (bundle != null) {
                    f3137f = Boolean.valueOf(bundle.getBoolean("autoStoreLocales"));
                }
            } catch (PackageManager.NameNotFoundException unused) {
                Log.d("AppCompatDelegate", "Checking for metadata for AppLocalesMetadataHolderService : Service not found");
                f3137f = Boolean.FALSE;
            }
        }
        return f3137f.booleanValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void x(Context context) {
        Q(context);
        f3138g = true;
    }

    public abstract void A();

    public abstract void B(Bundle bundle);

    public abstract void C();

    public abstract void D(Bundle bundle);

    public abstract void E();

    public abstract void F();

    public abstract boolean I(int i3);

    public abstract void J(int i3);

    public abstract void K(View view);

    public abstract void L(View view, ViewGroup.LayoutParams layoutParams);

    public void N(OnBackInvokedDispatcher onBackInvokedDispatcher) {
    }

    public abstract void O(int i3);

    public abstract void P(CharSequence charSequence);

    public abstract void e(View view, ViewGroup.LayoutParams layoutParams);

    public abstract boolean f();

    public void h(Context context) {
    }

    public Context i(Context context) {
        h(context);
        return context;
    }

    public abstract View l(int i3);

    public abstract Context n();

    public abstract int p();

    public abstract MenuInflater r();

    public abstract androidx.appcompat.app.a t();

    public abstract void u();

    public abstract void v();

    public abstract void y(Configuration configuration);

    public abstract void z(Bundle bundle);
}
