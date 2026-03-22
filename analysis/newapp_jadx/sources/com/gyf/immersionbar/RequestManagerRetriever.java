package com.gyf.immersionbar;

import android.app.Activity;
import android.app.Dialog;
import android.app.FragmentManager;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class RequestManagerRetriever implements Handler.Callback {
    private static final int ID_REMOVE_FRAGMENT_MANAGER = 1;
    private static final int ID_REMOVE_SUPPORT_FRAGMENT_MANAGER = 2;
    private Handler mHandler;
    private final Map<FragmentManager, RequestManagerFragment> mPendingFragments;
    private final Map<androidx.fragment.app.FragmentManager, SupportRequestManagerFragment> mPendingSupportFragments;
    private String mTag;

    public static class Holder {
        private static final RequestManagerRetriever INSTANCE = new RequestManagerRetriever();

        private Holder() {
        }
    }

    private static <T> void checkNotNull(@Nullable T t, @NonNull String str) {
        Objects.requireNonNull(t, str);
    }

    private RequestManagerFragment getFragment(FragmentManager fragmentManager, String str) {
        return getFragment(fragmentManager, str, false);
    }

    public static RequestManagerRetriever getInstance() {
        return Holder.INSTANCE;
    }

    private SupportRequestManagerFragment getSupportFragment(androidx.fragment.app.FragmentManager fragmentManager, String str) {
        return getSupportFragment(fragmentManager, str, false);
    }

    public void destroy(Fragment fragment, boolean z) {
        String sb;
        if (fragment == null) {
            return;
        }
        String str = this.mTag;
        if (z) {
            StringBuilder m586H = C1499a.m586H(str);
            m586H.append(fragment.getClass().getName());
            sb = m586H.toString();
        } else {
            StringBuilder m586H2 = C1499a.m586H(str);
            m586H2.append(System.identityHashCode(fragment));
            sb = m586H2.toString();
        }
        getSupportFragment(fragment.getChildFragmentManager(), sb, true);
    }

    public ImmersionBar get(Activity activity) {
        checkNotNull(activity, "activity is null");
        String str = this.mTag + System.identityHashCode(activity);
        return activity instanceof FragmentActivity ? getSupportFragment(((FragmentActivity) activity).getSupportFragmentManager(), str).get(activity) : getFragment(activity.getFragmentManager(), str).get(activity);
    }

    @Override // android.os.Handler.Callback
    public boolean handleMessage(Message message) {
        int i2 = message.what;
        if (i2 == 1) {
            this.mPendingFragments.remove((FragmentManager) message.obj);
            return true;
        }
        if (i2 != 2) {
            return false;
        }
        this.mPendingSupportFragments.remove((androidx.fragment.app.FragmentManager) message.obj);
        return true;
    }

    private RequestManagerRetriever() {
        this.mTag = ImmersionBar.class.getName();
        this.mPendingFragments = new HashMap();
        this.mPendingSupportFragments = new HashMap();
        this.mHandler = new Handler(Looper.getMainLooper(), this);
    }

    private RequestManagerFragment getFragment(FragmentManager fragmentManager, String str, boolean z) {
        RequestManagerFragment requestManagerFragment = (RequestManagerFragment) fragmentManager.findFragmentByTag(str);
        if (requestManagerFragment == null && (requestManagerFragment = this.mPendingFragments.get(fragmentManager)) == null) {
            if (z) {
                return null;
            }
            requestManagerFragment = new RequestManagerFragment();
            this.mPendingFragments.put(fragmentManager, requestManagerFragment);
            fragmentManager.beginTransaction().add(requestManagerFragment, str).commitAllowingStateLoss();
            this.mHandler.obtainMessage(1, fragmentManager).sendToTarget();
        }
        if (!z) {
            return requestManagerFragment;
        }
        fragmentManager.beginTransaction().remove(requestManagerFragment).commitAllowingStateLoss();
        return null;
    }

    private SupportRequestManagerFragment getSupportFragment(androidx.fragment.app.FragmentManager fragmentManager, String str, boolean z) {
        SupportRequestManagerFragment supportRequestManagerFragment = (SupportRequestManagerFragment) fragmentManager.findFragmentByTag(str);
        if (supportRequestManagerFragment == null && (supportRequestManagerFragment = this.mPendingSupportFragments.get(fragmentManager)) == null) {
            if (z) {
                return null;
            }
            supportRequestManagerFragment = new SupportRequestManagerFragment();
            this.mPendingSupportFragments.put(fragmentManager, supportRequestManagerFragment);
            fragmentManager.beginTransaction().add(supportRequestManagerFragment, str).commitAllowingStateLoss();
            this.mHandler.obtainMessage(2, fragmentManager).sendToTarget();
        }
        if (!z) {
            return supportRequestManagerFragment;
        }
        fragmentManager.beginTransaction().remove(supportRequestManagerFragment).commitAllowingStateLoss();
        return null;
    }

    public void destroy(Activity activity, Dialog dialog) {
        if (activity == null || dialog == null) {
            return;
        }
        String str = this.mTag + System.identityHashCode(dialog);
        if (activity instanceof FragmentActivity) {
            SupportRequestManagerFragment supportFragment = getSupportFragment(((FragmentActivity) activity).getSupportFragmentManager(), str, true);
            if (supportFragment != null) {
                supportFragment.get(activity, dialog).onDestroy();
                return;
            }
            return;
        }
        RequestManagerFragment fragment = getFragment(activity.getFragmentManager(), str, true);
        if (fragment != null) {
            fragment.get(activity, dialog).onDestroy();
        }
    }

    public ImmersionBar get(Fragment fragment, boolean z) {
        String sb;
        checkNotNull(fragment, "fragment is null");
        checkNotNull(fragment.getActivity(), "fragment.getActivity() is null");
        if (fragment instanceof DialogFragment) {
            checkNotNull(((DialogFragment) fragment).getDialog(), "fragment.getDialog() is null");
        }
        String str = this.mTag;
        if (z) {
            StringBuilder m586H = C1499a.m586H(str);
            m586H.append(fragment.getClass().getName());
            sb = m586H.toString();
        } else {
            StringBuilder m586H2 = C1499a.m586H(str);
            m586H2.append(System.identityHashCode(fragment));
            sb = m586H2.toString();
        }
        return getSupportFragment(fragment.getChildFragmentManager(), sb).get(fragment);
    }

    @RequiresApi(api = 17)
    public ImmersionBar get(android.app.Fragment fragment, boolean z) {
        String sb;
        checkNotNull(fragment, "fragment is null");
        checkNotNull(fragment.getActivity(), "fragment.getActivity() is null");
        if (fragment instanceof android.app.DialogFragment) {
            checkNotNull(((android.app.DialogFragment) fragment).getDialog(), "fragment.getDialog() is null");
        }
        String str = this.mTag;
        if (z) {
            StringBuilder m586H = C1499a.m586H(str);
            m586H.append(fragment.getClass().getName());
            sb = m586H.toString();
        } else {
            StringBuilder m586H2 = C1499a.m586H(str);
            m586H2.append(System.identityHashCode(fragment));
            sb = m586H2.toString();
        }
        return getFragment(fragment.getChildFragmentManager(), sb).get(fragment);
    }

    public ImmersionBar get(Activity activity, Dialog dialog) {
        checkNotNull(activity, "activity is null");
        checkNotNull(dialog, "dialog is null");
        String str = this.mTag + System.identityHashCode(dialog);
        if (activity instanceof FragmentActivity) {
            return getSupportFragment(((FragmentActivity) activity).getSupportFragmentManager(), str).get(activity, dialog);
        }
        return getFragment(activity.getFragmentManager(), str).get(activity, dialog);
    }
}
