package l0;

import I0.C0194t;
import I0.C0195u;
import I0.y;
import I0.z;
import android.content.Context;
import java.lang.reflect.InvocationTargetException;

/* JADX INFO: renamed from: l0.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0616d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final Class f9489a = AbstractC0616d.class;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static C0619g f9490b = null;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static volatile boolean f9491c = false;

    public static C0194t a() {
        return b().j();
    }

    public static y b() {
        return y.l();
    }

    public static void c(Context context, C0195u c0195u, C0614b c0614b) {
        d(context, c0195u, c0614b, true);
    }

    public static void d(Context context, C0195u c0195u, C0614b c0614b, boolean z3) {
        if (U0.b.d()) {
            U0.b.a("Fresco#initialize");
        }
        if (f9491c) {
            Y.a.E(f9489a, "Fresco has already been initialized! `Fresco.initialize(...)` should only be called 1 single time to avoid memory leaks!");
        } else {
            f9491c = true;
        }
        z.b(z3);
        if (!Z1.a.c()) {
            if (U0.b.d()) {
                U0.b.a("Fresco.initialize->SoLoader.init");
            }
            try {
                try {
                    try {
                        try {
                            Class.forName("com.facebook.imagepipeline.nativecode.NativeCodeInitializer").getMethod("init", Context.class).invoke(null, context);
                        } catch (ClassNotFoundException unused) {
                            Z1.a.b(new Z1.c());
                            if (U0.b.d()) {
                            }
                        }
                    } catch (NoSuchMethodException unused2) {
                        Z1.a.b(new Z1.c());
                        if (U0.b.d()) {
                        }
                    }
                } catch (IllegalAccessException unused3) {
                    Z1.a.b(new Z1.c());
                    if (U0.b.d()) {
                    }
                } catch (InvocationTargetException unused4) {
                    Z1.a.b(new Z1.c());
                    if (U0.b.d()) {
                    }
                }
                if (U0.b.d()) {
                    U0.b.b();
                }
            } catch (Throwable th) {
                if (U0.b.d()) {
                    U0.b.b();
                }
                throw th;
            }
        }
        Context applicationContext = context.getApplicationContext();
        if (c0195u == null) {
            y.t(applicationContext);
        } else {
            y.s(c0195u);
        }
        e(applicationContext, c0614b);
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    private static void e(Context context, C0614b c0614b) {
        if (U0.b.d()) {
            U0.b.a("Fresco.initializeDrawee");
        }
        C0619g c0619g = new C0619g(context, c0614b);
        f9490b = c0619g;
        w0.e.g(c0619g);
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    public static C0618f f() {
        return f9490b.get();
    }
}
