package B;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.x;
import i2.AbstractC0586n;
import i2.D;
import i2.K;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final c f57a = new c();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static C0001c f58b = C0001c.f69d;

    public enum a {
        PENALTY_LOG,
        PENALTY_DEATH,
        DETECT_FRAGMENT_REUSE,
        DETECT_FRAGMENT_TAG_USAGE,
        DETECT_RETAIN_INSTANCE_USAGE,
        DETECT_SET_USER_VISIBLE_HINT,
        DETECT_TARGET_FRAGMENT_USAGE,
        DETECT_WRONG_FRAGMENT_CONTAINER
    }

    public interface b {
    }

    /* JADX INFO: renamed from: B.c$c, reason: collision with other inner class name */
    public static final class C0001c {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final a f68c = new a(null);

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public static final C0001c f69d = new C0001c(K.b(), null, D.f());

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Set f70a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Map f71b;

        /* JADX INFO: renamed from: B.c$c$a */
        public static final class a {
            public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            private a() {
            }
        }

        public C0001c(Set set, b bVar, Map map) {
            j.f(set, "flags");
            j.f(map, "allowedViolations");
            this.f70a = set;
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            for (Map.Entry entry : map.entrySet()) {
                linkedHashMap.put((String) entry.getKey(), (Set) entry.getValue());
            }
            this.f71b = linkedHashMap;
        }

        public final Set a() {
            return this.f70a;
        }

        public final b b() {
            return null;
        }

        public final Map c() {
            return this.f71b;
        }
    }

    private c() {
    }

    private final C0001c b(Fragment fragment) {
        while (fragment != null) {
            if (fragment.V()) {
                x xVarD = fragment.D();
                j.e(xVarD, "declaringFragment.parentFragmentManager");
                if (xVarD.z0() != null) {
                    C0001c c0001cZ0 = xVarD.z0();
                    j.c(c0001cZ0);
                    return c0001cZ0;
                }
            }
            fragment = fragment.C();
        }
        return f58b;
    }

    private final void c(C0001c c0001c, final g gVar) {
        Fragment fragmentA = gVar.a();
        final String name = fragmentA.getClass().getName();
        if (c0001c.a().contains(a.PENALTY_LOG)) {
            Log.d("FragmentStrictMode", "Policy violation in " + name, gVar);
        }
        c0001c.b();
        if (c0001c.a().contains(a.PENALTY_DEATH)) {
            j(fragmentA, new Runnable() { // from class: B.b
                @Override // java.lang.Runnable
                public final void run() {
                    c.d(name, gVar);
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void d(String str, g gVar) {
        j.f(gVar, "$violation");
        Log.e("FragmentStrictMode", "Policy violation with PENALTY_DEATH in " + str, gVar);
        throw gVar;
    }

    private final void e(g gVar) {
        if (x.G0(3)) {
            Log.d("FragmentManager", "StrictMode violation in " + gVar.a().getClass().getName(), gVar);
        }
    }

    public static final void f(Fragment fragment, String str) {
        j.f(fragment, "fragment");
        j.f(str, "previousFragmentId");
        B.a aVar = new B.a(fragment, str);
        c cVar = f57a;
        cVar.e(aVar);
        C0001c c0001cB = cVar.b(fragment);
        if (c0001cB.a().contains(a.DETECT_FRAGMENT_REUSE) && cVar.k(c0001cB, fragment.getClass(), aVar.getClass())) {
            cVar.c(c0001cB, aVar);
        }
    }

    public static final void g(Fragment fragment, ViewGroup viewGroup) {
        j.f(fragment, "fragment");
        d dVar = new d(fragment, viewGroup);
        c cVar = f57a;
        cVar.e(dVar);
        C0001c c0001cB = cVar.b(fragment);
        if (c0001cB.a().contains(a.DETECT_FRAGMENT_TAG_USAGE) && cVar.k(c0001cB, fragment.getClass(), dVar.getClass())) {
            cVar.c(c0001cB, dVar);
        }
    }

    public static final void h(Fragment fragment) {
        j.f(fragment, "fragment");
        e eVar = new e(fragment);
        c cVar = f57a;
        cVar.e(eVar);
        C0001c c0001cB = cVar.b(fragment);
        if (c0001cB.a().contains(a.DETECT_TARGET_FRAGMENT_USAGE) && cVar.k(c0001cB, fragment.getClass(), eVar.getClass())) {
            cVar.c(c0001cB, eVar);
        }
    }

    public static final void i(Fragment fragment, ViewGroup viewGroup) {
        j.f(fragment, "fragment");
        j.f(viewGroup, "container");
        h hVar = new h(fragment, viewGroup);
        c cVar = f57a;
        cVar.e(hVar);
        C0001c c0001cB = cVar.b(fragment);
        if (c0001cB.a().contains(a.DETECT_WRONG_FRAGMENT_CONTAINER) && cVar.k(c0001cB, fragment.getClass(), hVar.getClass())) {
            cVar.c(c0001cB, hVar);
        }
    }

    private final void j(Fragment fragment, Runnable runnable) {
        if (!fragment.V()) {
            runnable.run();
            return;
        }
        Handler handlerO = fragment.D().t0().o();
        j.e(handlerO, "fragment.parentFragmentManager.host.handler");
        if (j.b(handlerO.getLooper(), Looper.myLooper())) {
            runnable.run();
        } else {
            handlerO.post(runnable);
        }
    }

    private final boolean k(C0001c c0001c, Class cls, Class cls2) {
        Set set = (Set) c0001c.c().get(cls.getName());
        if (set == null) {
            return true;
        }
        if (j.b(cls2.getSuperclass(), g.class) || !AbstractC0586n.A(set, cls2.getSuperclass())) {
            return !set.contains(cls2);
        }
        return false;
    }
}
