package p005b.p293n.p294a;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p293n.p294a.C2641c0;

/* renamed from: b.n.a.i0 */
/* loaded from: classes2.dex */
public final class RunnableC2653i0 extends AbstractFragmentC2649g0 implements Runnable {

    /* renamed from: g */
    @Nullable
    public InterfaceC2658l f7258g;

    @Override // p005b.p293n.p294a.AbstractFragmentC2649g0
    /* renamed from: c */
    public void mo3137c() {
        ArrayList<String> stringArrayList;
        Bundle arguments = getArguments();
        Activity activity = getActivity();
        if (arguments == null || activity == null || (stringArrayList = arguments.getStringArrayList("request_permissions")) == null || stringArrayList.isEmpty()) {
            return;
        }
        C2650h.m3151n(new C2663q(this, null), C2665s.m3160b(activity, stringArrayList), 1025);
    }

    @Override // android.app.Fragment
    public void onActivityResult(int i2, int i3, @Nullable Intent intent) {
        ArrayList<String> stringArrayList;
        if (i2 != 1025) {
            return;
        }
        Activity activity = getActivity();
        Bundle arguments = getArguments();
        if (activity == null || arguments == null || (stringArrayList = arguments.getStringArrayList("request_permissions")) == null || stringArrayList.isEmpty()) {
            return;
        }
        long j2 = 300;
        long j3 = C2354n.m2378B0() ? 200L : 300L;
        if (!(!TextUtils.isEmpty(C2645e0.m3125k("ro.build.version.emui"))) && !C2647f0.m3131d()) {
            j2 = (C2647f0.m3132e() && C2354n.m2378B0() && C2645e0.m3119e(stringArrayList, "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS")) ? 1000L : j3;
        } else if (!C2354n.m2393G0()) {
            j2 = 500;
        }
        C2645e0.f7223a.postDelayed(this, j2);
    }

    @Override // java.lang.Runnable
    public void run() {
        Activity activity;
        if (isAdded() && (activity = getActivity()) != null) {
            InterfaceC2658l interfaceC2658l = this.f7258g;
            this.f7258g = null;
            if (interfaceC2658l == null) {
                m3136b(activity);
                return;
            }
            ArrayList<String> stringArrayList = getArguments().getStringArrayList("request_permissions");
            if (stringArrayList == null || stringArrayList.isEmpty()) {
                return;
            }
            ArrayList arrayList = new ArrayList(stringArrayList.size());
            for (String str : stringArrayList) {
                if (C2665s.m3161c(activity, str)) {
                    arrayList.add(str);
                }
            }
            if (arrayList.size() == stringArrayList.size()) {
                ((C2641c0.b) interfaceC2658l).f7207a.run();
            } else {
                ((C2641c0.b) interfaceC2658l).f7207a.run();
            }
            m3136b(activity);
        }
    }
}
