package androidx.fragment.app;

import android.view.View;
import java.util.ArrayList;
import l.C0606a;

/* JADX INFO: loaded from: classes.dex */
abstract class G {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    static final I f4838a = new H();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    static final I f4839b = b();

    static void a(Fragment fragment, Fragment fragment2, boolean z3, C0606a c0606a, boolean z4) {
        if (z3) {
            fragment2.t();
        } else {
            fragment.t();
        }
    }

    private static I b() {
        try {
            return (I) Class.forName("androidx.transition.FragmentTransitionSupport").getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
        } catch (Exception unused) {
            return null;
        }
    }

    static void c(C0606a c0606a, C0606a c0606a2) {
        for (int size = c0606a.size() - 1; size >= 0; size--) {
            if (!c0606a2.containsKey((String) c0606a.l(size))) {
                c0606a.j(size);
            }
        }
    }

    static void d(ArrayList arrayList, int i3) {
        if (arrayList == null) {
            return;
        }
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            ((View) arrayList.get(size)).setVisibility(i3);
        }
    }
}
