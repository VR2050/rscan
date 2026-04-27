package androidx.startup;

import G.b;
import G.c;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static volatile a f5276d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final Object f5277e = new Object();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final Context f5280c;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final Set f5279b = new HashSet();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final Map f5278a = new HashMap();

    a(Context context) {
        this.f5280c = context.getApplicationContext();
    }

    private Object d(Class cls, Set set) {
        Object objB;
        if (I.a.h()) {
            try {
                I.a.c(cls.getSimpleName());
            } catch (Throwable th) {
                I.a.f();
                throw th;
            }
        }
        if (set.contains(cls)) {
            throw new IllegalStateException(String.format("Cannot initialize %s. Cycle detected.", cls.getName()));
        }
        if (this.f5278a.containsKey(cls)) {
            objB = this.f5278a.get(cls);
        } else {
            set.add(cls);
            try {
                G.a aVar = (G.a) cls.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                List<Class> listA = aVar.a();
                if (!listA.isEmpty()) {
                    for (Class cls2 : listA) {
                        if (!this.f5278a.containsKey(cls2)) {
                            d(cls2, set);
                        }
                    }
                }
                objB = aVar.b(this.f5280c);
                set.remove(cls);
                this.f5278a.put(cls, objB);
            } catch (Throwable th2) {
                throw new c(th2);
            }
        }
        I.a.f();
        return objB;
    }

    public static a e(Context context) {
        if (f5276d == null) {
            synchronized (f5277e) {
                try {
                    if (f5276d == null) {
                        f5276d = new a(context);
                    }
                } finally {
                }
            }
        }
        return f5276d;
    }

    void a() {
        try {
            try {
                I.a.c("Startup");
                b(this.f5280c.getPackageManager().getProviderInfo(new ComponentName(this.f5280c.getPackageName(), InitializationProvider.class.getName()), 128).metaData);
            } catch (PackageManager.NameNotFoundException e3) {
                throw new c(e3);
            }
        } finally {
            I.a.f();
        }
    }

    void b(Bundle bundle) {
        String string = this.f5280c.getString(b.f763a);
        if (bundle != null) {
            try {
                HashSet hashSet = new HashSet();
                for (String str : bundle.keySet()) {
                    if (string.equals(bundle.getString(str, null))) {
                        Class<?> cls = Class.forName(str);
                        if (G.a.class.isAssignableFrom(cls)) {
                            this.f5279b.add(cls);
                        }
                    }
                }
                Iterator it = this.f5279b.iterator();
                while (it.hasNext()) {
                    d((Class) it.next(), hashSet);
                }
            } catch (ClassNotFoundException e3) {
                throw new c(e3);
            }
        }
    }

    Object c(Class cls) {
        Object objD;
        synchronized (f5277e) {
            try {
                objD = this.f5278a.get(cls);
                if (objD == null) {
                    objD = d(cls, new HashSet());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return objD;
    }

    public Object f(Class cls) {
        return c(cls);
    }

    public boolean g(Class cls) {
        return this.f5279b.contains(cls);
    }
}
