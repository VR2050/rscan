package com.bumptech.glide.manager;

import android.content.Context;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.ComponentCallbacks2C1559i;
import p005b.p143g.p144a.p163n.C1747a;
import p005b.p143g.p144a.p163n.C1758l;
import p005b.p143g.p144a.p163n.InterfaceC1759m;

/* loaded from: classes.dex */
public class SupportRequestManagerFragment extends Fragment {

    /* renamed from: c */
    public final C1747a f8855c;

    /* renamed from: e */
    public final InterfaceC1759m f8856e;

    /* renamed from: f */
    public final Set<SupportRequestManagerFragment> f8857f;

    /* renamed from: g */
    @Nullable
    public SupportRequestManagerFragment f8858g;

    /* renamed from: h */
    @Nullable
    public ComponentCallbacks2C1559i f8859h;

    /* renamed from: i */
    @Nullable
    public Fragment f8860i;

    /* renamed from: com.bumptech.glide.manager.SupportRequestManagerFragment$a */
    public class C3222a implements InterfaceC1759m {
        public C3222a() {
        }

        public String toString() {
            return super.toString() + "{fragment=" + SupportRequestManagerFragment.this + "}";
        }
    }

    public SupportRequestManagerFragment() {
        C1747a c1747a = new C1747a();
        this.f8856e = new C3222a();
        this.f8857f = new HashSet();
        this.f8855c = c1747a;
    }

    @Nullable
    /* renamed from: g */
    public final Fragment m3896g() {
        Fragment parentFragment = getParentFragment();
        return parentFragment != null ? parentFragment : this.f8860i;
    }

    /* renamed from: h */
    public final void m3897h(@NonNull Context context, @NonNull FragmentManager fragmentManager) {
        m3898i();
        C1758l c1758l = ComponentCallbacks2C1553c.m735d(context).f1816l;
        Objects.requireNonNull(c1758l);
        SupportRequestManagerFragment m1058j = c1758l.m1058j(fragmentManager, null, C1758l.m1050k(context));
        this.f8858g = m1058j;
        if (equals(m1058j)) {
            return;
        }
        this.f8858g.f8857f.add(this);
    }

    /* renamed from: i */
    public final void m3898i() {
        SupportRequestManagerFragment supportRequestManagerFragment = this.f8858g;
        if (supportRequestManagerFragment != null) {
            supportRequestManagerFragment.f8857f.remove(this);
            this.f8858g = null;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        Fragment fragment = this;
        while (fragment.getParentFragment() != null) {
            fragment = fragment.getParentFragment();
        }
        FragmentManager fragmentManager = fragment.getFragmentManager();
        if (fragmentManager == null) {
            Log.isLoggable("SupportRMFragment", 5);
            return;
        }
        try {
            m3897h(getContext(), fragmentManager);
        } catch (IllegalStateException unused) {
            Log.isLoggable("SupportRMFragment", 5);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        this.f8855c.m1042c();
        m3898i();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDetach() {
        super.onDetach();
        this.f8860i = null;
        m3898i();
    }

    @Override // androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        this.f8855c.m1043d();
    }

    @Override // androidx.fragment.app.Fragment
    public void onStop() {
        super.onStop();
        this.f8855c.m1044e();
    }

    @Override // androidx.fragment.app.Fragment
    public String toString() {
        return super.toString() + "{parent=" + m3896g() + "}";
    }
}
