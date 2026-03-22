package p005b.p143g.p144a.p163n;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.Application;
import android.app.FragmentManager;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.collection.ArrayMap;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import com.bumptech.glide.manager.SupportRequestManagerFragment;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.ComponentCallbacks2C1559i;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.n.l */
/* loaded from: classes.dex */
public class C1758l implements Handler.Callback {

    /* renamed from: c */
    public static final b f2623c = new a();

    /* renamed from: e */
    public volatile ComponentCallbacks2C1559i f2624e;

    /* renamed from: h */
    public final Handler f2627h;

    /* renamed from: i */
    public final b f2628i;

    /* renamed from: f */
    @VisibleForTesting
    public final Map<FragmentManager, FragmentC1757k> f2625f = new HashMap();

    /* renamed from: g */
    @VisibleForTesting
    public final Map<androidx.fragment.app.FragmentManager, SupportRequestManagerFragment> f2626g = new HashMap();

    /* renamed from: j */
    public final ArrayMap<View, Fragment> f2629j = new ArrayMap<>();

    /* renamed from: k */
    public final ArrayMap<View, android.app.Fragment> f2630k = new ArrayMap<>();

    /* renamed from: l */
    public final Bundle f2631l = new Bundle();

    /* renamed from: b.g.a.n.l$a */
    public class a implements b {
        @Override // p005b.p143g.p144a.p163n.C1758l.b
        @NonNull
        /* renamed from: a */
        public ComponentCallbacks2C1559i mo733a(@NonNull ComponentCallbacks2C1553c componentCallbacks2C1553c, @NonNull InterfaceC1754h interfaceC1754h, @NonNull InterfaceC1759m interfaceC1759m, @NonNull Context context) {
            return new ComponentCallbacks2C1559i(componentCallbacks2C1553c, interfaceC1754h, interfaceC1759m, context);
        }
    }

    /* renamed from: b.g.a.n.l$b */
    public interface b {
        @NonNull
        /* renamed from: a */
        ComponentCallbacks2C1559i mo733a(@NonNull ComponentCallbacks2C1553c componentCallbacks2C1553c, @NonNull InterfaceC1754h interfaceC1754h, @NonNull InterfaceC1759m interfaceC1759m, @NonNull Context context);
    }

    public C1758l(@Nullable b bVar) {
        this.f2628i = bVar == null ? f2623c : bVar;
        this.f2627h = new Handler(Looper.getMainLooper(), this);
    }

    @Nullable
    /* renamed from: a */
    public static Activity m1048a(@NonNull Context context) {
        if (context instanceof Activity) {
            return (Activity) context;
        }
        if (context instanceof ContextWrapper) {
            return m1048a(((ContextWrapper) context).getBaseContext());
        }
        return null;
    }

    /* renamed from: c */
    public static void m1049c(@Nullable Collection<Fragment> collection, @NonNull Map<View, Fragment> map) {
        if (collection == null) {
            return;
        }
        for (Fragment fragment : collection) {
            if (fragment != null && fragment.getView() != null) {
                map.put(fragment.getView(), fragment);
                m1049c(fragment.getChildFragmentManager().getFragments(), map);
            }
        }
    }

    /* renamed from: k */
    public static boolean m1050k(Context context) {
        Activity m1048a = m1048a(context);
        return m1048a == null || !m1048a.isFinishing();
    }

    @TargetApi(26)
    @Deprecated
    /* renamed from: b */
    public final void m1051b(@NonNull FragmentManager fragmentManager, @NonNull ArrayMap<View, android.app.Fragment> arrayMap) {
        if (Build.VERSION.SDK_INT >= 26) {
            for (android.app.Fragment fragment : fragmentManager.getFragments()) {
                if (fragment.getView() != null) {
                    arrayMap.put(fragment.getView(), fragment);
                    m1051b(fragment.getChildFragmentManager(), arrayMap);
                }
            }
            return;
        }
        int i2 = 0;
        while (true) {
            int i3 = i2 + 1;
            this.f2631l.putInt("key", i2);
            android.app.Fragment fragment2 = null;
            try {
                fragment2 = fragmentManager.getFragment(this.f2631l, "key");
            } catch (Exception unused) {
            }
            if (fragment2 == null) {
                return;
            }
            if (fragment2.getView() != null) {
                arrayMap.put(fragment2.getView(), fragment2);
                m1051b(fragment2.getChildFragmentManager(), arrayMap);
            }
            i2 = i3;
        }
    }

    @NonNull
    @Deprecated
    /* renamed from: d */
    public final ComponentCallbacks2C1559i m1052d(@NonNull Context context, @NonNull FragmentManager fragmentManager, @Nullable android.app.Fragment fragment, boolean z) {
        FragmentC1757k m1057i = m1057i(fragmentManager, fragment, z);
        ComponentCallbacks2C1559i componentCallbacks2C1559i = m1057i.f2619g;
        if (componentCallbacks2C1559i != null) {
            return componentCallbacks2C1559i;
        }
        ComponentCallbacks2C1559i mo733a = this.f2628i.mo733a(ComponentCallbacks2C1553c.m735d(context), m1057i.f2616c, m1057i.f2617e, context);
        m1057i.f2619g = mo733a;
        return mo733a;
    }

    @NonNull
    /* renamed from: e */
    public ComponentCallbacks2C1559i m1053e(@NonNull Activity activity) {
        if (C1807i.m1150g()) {
            return m1054f(activity.getApplicationContext());
        }
        if (activity.isDestroyed()) {
            throw new IllegalArgumentException("You cannot start a load for a destroyed activity");
        }
        return m1052d(activity, activity.getFragmentManager(), null, m1050k(activity));
    }

    @NonNull
    /* renamed from: f */
    public ComponentCallbacks2C1559i m1054f(@NonNull Context context) {
        if (context == null) {
            throw new IllegalArgumentException("You cannot start a load on a null Context");
        }
        if (C1807i.m1151h() && !(context instanceof Application)) {
            if (context instanceof FragmentActivity) {
                return m1056h((FragmentActivity) context);
            }
            if (context instanceof Activity) {
                return m1053e((Activity) context);
            }
            if (context instanceof ContextWrapper) {
                ContextWrapper contextWrapper = (ContextWrapper) context;
                if (contextWrapper.getBaseContext().getApplicationContext() != null) {
                    return m1054f(contextWrapper.getBaseContext());
                }
            }
        }
        if (this.f2624e == null) {
            synchronized (this) {
                if (this.f2624e == null) {
                    this.f2624e = this.f2628i.mo733a(ComponentCallbacks2C1553c.m735d(context.getApplicationContext()), new C1748b(), new C1753g(), context.getApplicationContext());
                }
            }
        }
        return this.f2624e;
    }

    @NonNull
    /* renamed from: g */
    public ComponentCallbacks2C1559i m1055g(@NonNull Fragment fragment) {
        Objects.requireNonNull(fragment.getContext(), "You cannot start a load on a fragment before it is attached or after it is destroyed");
        if (C1807i.m1150g()) {
            return m1054f(fragment.getContext().getApplicationContext());
        }
        return m1059l(fragment.getContext(), fragment.getChildFragmentManager(), fragment, fragment.isVisible());
    }

    @NonNull
    /* renamed from: h */
    public ComponentCallbacks2C1559i m1056h(@NonNull FragmentActivity fragmentActivity) {
        if (C1807i.m1150g()) {
            return m1054f(fragmentActivity.getApplicationContext());
        }
        if (fragmentActivity.isDestroyed()) {
            throw new IllegalArgumentException("You cannot start a load for a destroyed activity");
        }
        return m1059l(fragmentActivity, fragmentActivity.getSupportFragmentManager(), null, m1050k(fragmentActivity));
    }

    @Override // android.os.Handler.Callback
    public boolean handleMessage(Message message) {
        Object obj;
        Object remove;
        Object obj2;
        int i2 = message.what;
        Object obj3 = null;
        boolean z = true;
        if (i2 == 1) {
            obj = (FragmentManager) message.obj;
            remove = this.f2625f.remove(obj);
        } else {
            if (i2 != 2) {
                z = false;
                obj2 = null;
                if (z && obj3 == null && Log.isLoggable("RMRetriever", 5)) {
                    String str = "Failed to remove expected request manager fragment, manager: " + obj2;
                }
                return z;
            }
            obj = (androidx.fragment.app.FragmentManager) message.obj;
            remove = this.f2626g.remove(obj);
        }
        Object obj4 = obj;
        obj3 = remove;
        obj2 = obj4;
        if (z) {
            String str2 = "Failed to remove expected request manager fragment, manager: " + obj2;
        }
        return z;
    }

    @NonNull
    /* renamed from: i */
    public final FragmentC1757k m1057i(@NonNull FragmentManager fragmentManager, @Nullable android.app.Fragment fragment, boolean z) {
        FragmentC1757k fragmentC1757k = (FragmentC1757k) fragmentManager.findFragmentByTag("com.bumptech.glide.manager");
        if (fragmentC1757k == null && (fragmentC1757k = this.f2625f.get(fragmentManager)) == null) {
            fragmentC1757k = new FragmentC1757k();
            fragmentC1757k.f2621i = fragment;
            if (fragment != null && fragment.getActivity() != null) {
                fragmentC1757k.m1046a(fragment.getActivity());
            }
            if (z) {
                fragmentC1757k.f2616c.m1043d();
            }
            this.f2625f.put(fragmentManager, fragmentC1757k);
            fragmentManager.beginTransaction().add(fragmentC1757k, "com.bumptech.glide.manager").commitAllowingStateLoss();
            this.f2627h.obtainMessage(1, fragmentManager).sendToTarget();
        }
        return fragmentC1757k;
    }

    @NonNull
    /* renamed from: j */
    public final SupportRequestManagerFragment m1058j(@NonNull androidx.fragment.app.FragmentManager fragmentManager, @Nullable Fragment fragment, boolean z) {
        SupportRequestManagerFragment supportRequestManagerFragment = (SupportRequestManagerFragment) fragmentManager.findFragmentByTag("com.bumptech.glide.manager");
        if (supportRequestManagerFragment == null && (supportRequestManagerFragment = this.f2626g.get(fragmentManager)) == null) {
            supportRequestManagerFragment = new SupportRequestManagerFragment();
            supportRequestManagerFragment.f8860i = fragment;
            if (fragment != null && fragment.getContext() != null) {
                Fragment fragment2 = fragment;
                while (fragment2.getParentFragment() != null) {
                    fragment2 = fragment2.getParentFragment();
                }
                androidx.fragment.app.FragmentManager fragmentManager2 = fragment2.getFragmentManager();
                if (fragmentManager2 != null) {
                    supportRequestManagerFragment.m3897h(fragment.getContext(), fragmentManager2);
                }
            }
            if (z) {
                supportRequestManagerFragment.f8855c.m1043d();
            }
            this.f2626g.put(fragmentManager, supportRequestManagerFragment);
            fragmentManager.beginTransaction().add(supportRequestManagerFragment, "com.bumptech.glide.manager").commitAllowingStateLoss();
            this.f2627h.obtainMessage(2, fragmentManager).sendToTarget();
        }
        return supportRequestManagerFragment;
    }

    @NonNull
    /* renamed from: l */
    public final ComponentCallbacks2C1559i m1059l(@NonNull Context context, @NonNull androidx.fragment.app.FragmentManager fragmentManager, @Nullable Fragment fragment, boolean z) {
        SupportRequestManagerFragment m1058j = m1058j(fragmentManager, fragment, z);
        ComponentCallbacks2C1559i componentCallbacks2C1559i = m1058j.f8859h;
        if (componentCallbacks2C1559i != null) {
            return componentCallbacks2C1559i;
        }
        ComponentCallbacks2C1559i mo733a = this.f2628i.mo733a(ComponentCallbacks2C1553c.m735d(context), m1058j.f8855c, m1058j.f8856e, context);
        m1058j.f8859h = mo733a;
        return mo733a;
    }
}
