package io.openinstall.sdk;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes3.dex */
public class bv {
    private static bv a;
    private final boolean b;
    private ca c;
    private Application f;
    private Application.ActivityLifecycleCallbacks g;
    private boolean d = true;
    private WeakReference<Activity> e = null;
    private final Runnable h = new bx(this);

    private bv(Context context) {
        boolean zBooleanValue = as.a().g().booleanValue();
        this.b = zBooleanValue;
        if (!zBooleanValue) {
            if (ec.a) {
                ec.a("clipBoardEnabled = false", new Object[0]);
            }
        } else {
            this.c = new ca(context);
            this.f = (Application) context.getApplicationContext();
            bw bwVar = new bw(this);
            this.g = bwVar;
            this.f.registerActivityLifecycleCallbacks(bwVar);
        }
    }

    public static bv a(Context context) {
        if (a == null) {
            synchronized (bv.class) {
                if (a == null) {
                    a = new bv(context);
                }
            }
        }
        return a;
    }

    public void a(String str) {
        if (this.b && this.d) {
            if (ec.a) {
                ec.a("%s release", str);
            }
            this.c.b();
        }
    }

    public void a(WeakReference<Activity> weakReference) {
        if (!this.b || weakReference == null) {
            return;
        }
        this.c.a(weakReference);
    }

    public void a(boolean z) {
        this.d = z;
    }

    public boolean a() {
        return this.b;
    }

    public by b() {
        return b(false);
    }

    public by b(boolean z) {
        Application.ActivityLifecycleCallbacks activityLifecycleCallbacks;
        if (!this.b) {
            return null;
        }
        by byVarA = by.a(z ? this.c.e() : this.c.d());
        if (byVarA != null) {
            if (ec.a) {
                ec.a("data type is %d", Integer.valueOf(byVarA.c()));
            }
            Application application = this.f;
            if (application != null && (activityLifecycleCallbacks = this.g) != null) {
                application.unregisterActivityLifecycleCallbacks(activityLifecycleCallbacks);
                this.g = null;
            }
        } else if (ec.a) {
            ec.a("data is null", new Object[0]);
        }
        return byVarA;
    }

    public void b(String str) {
        if (this.b && this.d) {
            if (ec.a) {
                ec.a("%s access", str);
            }
            this.c.a();
        }
    }
}
