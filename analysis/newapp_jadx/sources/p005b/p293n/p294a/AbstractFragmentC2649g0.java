package p005b.p293n.p294a;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentManager;
import android.content.Context;
import android.os.Handler;
import androidx.annotation.NonNull;

/* renamed from: b.n.a.g0 */
/* loaded from: classes2.dex */
public abstract class AbstractFragmentC2649g0 extends Fragment {

    /* renamed from: c */
    public boolean f7253c;

    /* renamed from: e */
    public boolean f7254e;

    /* renamed from: f */
    public int f7255f;

    /* renamed from: a */
    public void m3135a(@NonNull Activity activity) {
        FragmentManager fragmentManager = activity.getFragmentManager();
        if (fragmentManager == null) {
            return;
        }
        fragmentManager.beginTransaction().add(this, toString()).commitAllowingStateLoss();
    }

    /* renamed from: b */
    public void m3136b(@NonNull Activity activity) {
        FragmentManager fragmentManager = activity.getFragmentManager();
        if (fragmentManager == null) {
            return;
        }
        fragmentManager.beginTransaction().remove(this).commitAllowingStateLoss();
    }

    /* renamed from: c */
    public abstract void mo3137c();

    @Override // android.app.Fragment
    @SuppressLint({"SourceLockedOrientationActivity"})
    public void onAttach(Context context) {
        super.onAttach(context);
        Activity activity = getActivity();
        if (activity == null) {
            return;
        }
        int requestedOrientation = activity.getRequestedOrientation();
        this.f7255f = requestedOrientation;
        if (requestedOrientation != -1) {
            return;
        }
        Handler handler = C2645e0.f7223a;
        try {
            int i2 = activity.getResources().getConfiguration().orientation;
            if (i2 == 1) {
                activity.setRequestedOrientation(C2645e0.m3126l(activity) ? 9 : 1);
            } else if (i2 == 2) {
                activity.setRequestedOrientation(C2645e0.m3126l(activity) ? 8 : 0);
            }
        } catch (IllegalStateException e2) {
            e2.printStackTrace();
        }
    }

    @Override // android.app.Fragment
    public void onDetach() {
        super.onDetach();
        Activity activity = getActivity();
        if (activity == null || this.f7255f != -1 || activity.getRequestedOrientation() == -1) {
            return;
        }
        activity.setRequestedOrientation(-1);
    }

    @Override // android.app.Fragment
    public void onResume() {
        super.onResume();
        if (!this.f7253c) {
            m3136b(getActivity());
        } else {
            if (this.f7254e) {
                return;
            }
            this.f7254e = true;
            mo3137c();
        }
    }
}
