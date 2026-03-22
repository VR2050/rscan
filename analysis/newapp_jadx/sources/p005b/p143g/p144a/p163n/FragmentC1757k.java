package p005b.p143g.p144a.p163n;

import android.app.Activity;
import android.app.Fragment;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.ComponentCallbacks2C1559i;

@Deprecated
/* renamed from: b.g.a.n.k */
/* loaded from: classes.dex */
public class FragmentC1757k extends Fragment {

    /* renamed from: c */
    public final C1747a f2616c;

    /* renamed from: e */
    public final InterfaceC1759m f2617e;

    /* renamed from: f */
    public final Set<FragmentC1757k> f2618f;

    /* renamed from: g */
    @Nullable
    public ComponentCallbacks2C1559i f2619g;

    /* renamed from: h */
    @Nullable
    public FragmentC1757k f2620h;

    /* renamed from: i */
    @Nullable
    public Fragment f2621i;

    /* renamed from: b.g.a.n.k$a */
    public class a implements InterfaceC1759m {
        public a() {
        }

        public String toString() {
            return super.toString() + "{fragment=" + FragmentC1757k.this + "}";
        }
    }

    public FragmentC1757k() {
        C1747a c1747a = new C1747a();
        this.f2617e = new a();
        this.f2618f = new HashSet();
        this.f2616c = c1747a;
    }

    /* renamed from: a */
    public final void m1046a(@NonNull Activity activity) {
        m1047b();
        C1758l c1758l = ComponentCallbacks2C1553c.m735d(activity).f1816l;
        Objects.requireNonNull(c1758l);
        FragmentC1757k m1057i = c1758l.m1057i(activity.getFragmentManager(), null, C1758l.m1050k(activity));
        this.f2620h = m1057i;
        if (equals(m1057i)) {
            return;
        }
        this.f2620h.f2618f.add(this);
    }

    /* renamed from: b */
    public final void m1047b() {
        FragmentC1757k fragmentC1757k = this.f2620h;
        if (fragmentC1757k != null) {
            fragmentC1757k.f2618f.remove(this);
            this.f2620h = null;
        }
    }

    @Override // android.app.Fragment
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        try {
            m1046a(activity);
        } catch (IllegalStateException unused) {
            Log.isLoggable("RMFragment", 5);
        }
    }

    @Override // android.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        this.f2616c.m1042c();
        m1047b();
    }

    @Override // android.app.Fragment
    public void onDetach() {
        super.onDetach();
        m1047b();
    }

    @Override // android.app.Fragment
    public void onStart() {
        super.onStart();
        this.f2616c.m1043d();
    }

    @Override // android.app.Fragment
    public void onStop() {
        super.onStop();
        this.f2616c.m1044e();
    }

    @Override // android.app.Fragment
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append("{parent=");
        Fragment parentFragment = getParentFragment();
        if (parentFragment == null) {
            parentFragment = this.f2621i;
        }
        sb.append(parentFragment);
        sb.append("}");
        return sb.toString();
    }
}
