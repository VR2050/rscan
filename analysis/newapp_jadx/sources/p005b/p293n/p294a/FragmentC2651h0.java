package p005b.p293n.p294a;

import android.app.Activity;
import android.os.Bundle;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.n.a.h0 */
/* loaded from: classes2.dex */
public final class FragmentC2651h0 extends AbstractFragmentC2649g0 {

    /* renamed from: g */
    public static final List<Integer> f7256g = new ArrayList();

    /* renamed from: h */
    @Nullable
    public C2638b f7257h;

    @Override // p005b.p293n.p294a.AbstractFragmentC2649g0
    /* renamed from: c */
    public void mo3137c() {
        Bundle arguments = getArguments();
        Activity activity = getActivity();
        if (arguments == null || activity == null) {
            return;
        }
        ArrayList<String> stringArrayList = arguments.getStringArrayList("request_permissions");
        int i2 = arguments.getInt("request_code");
        if (stringArrayList == null || stringArrayList.isEmpty()) {
            return;
        }
        if (C2354n.m2390F0()) {
            requestPermissions((String[]) stringArrayList.toArray(new String[stringArrayList.size()]), i2);
            return;
        }
        int size = stringArrayList.size();
        int[] iArr = new int[size];
        for (int i3 = 0; i3 < size; i3++) {
            iArr[i3] = C2665s.m3161c(activity, stringArrayList.get(i3)) ? 0 : -1;
        }
        onRequestPermissionsResult(i2, (String[]) stringArrayList.toArray(new String[stringArrayList.size()]), iArr);
    }

    @Override // android.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        this.f7257h = null;
    }

    @Override // android.app.Fragment
    public void onRequestPermissionsResult(int i2, String[] strArr, int[] iArr) {
        Bundle arguments = getArguments();
        Activity activity = getActivity();
        if (activity == null || arguments == null || i2 != arguments.getInt("request_code") || strArr == null || strArr.length == 0 || iArr == null || iArr.length == 0) {
            return;
        }
        C2638b c2638b = this.f7257h;
        this.f7257h = null;
        f7256g.remove(Integer.valueOf(i2));
        if (c2638b != null) {
            c2638b.f7187a.run();
        }
        m3136b(activity);
    }
}
