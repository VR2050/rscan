package D0;

import G0.n;
import I0.InterfaceC0191p;
import V.d;
import java.util.concurrent.ExecutorService;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final b f591a = new b();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static boolean f592b;

    private b() {
    }

    public static final a a(F0.b bVar, InterfaceC0191p interfaceC0191p, n nVar, boolean z3, boolean z4, int i3, int i4, ExecutorService executorService) {
        if (f592b) {
            return null;
        }
        try {
            Class<?> cls = Class.forName("com.facebook.fresco.animation.factory.AnimatedFactoryV2Impl");
            Class cls2 = Boolean.TYPE;
            Class cls3 = Integer.TYPE;
            Object objNewInstance = cls.getConstructor(F0.b.class, InterfaceC0191p.class, n.class, cls2, cls2, cls3, cls3, d.class).newInstance(bVar, interfaceC0191p, nVar, Boolean.valueOf(z3), Boolean.valueOf(z4), Integer.valueOf(i3), Integer.valueOf(i4), executorService);
            j.d(objNewInstance, "null cannot be cast to non-null type com.facebook.imagepipeline.animated.factory.AnimatedFactory");
            androidx.activity.result.d.a(objNewInstance);
            return null;
        } catch (Throwable unused) {
            return null;
        }
    }
}
