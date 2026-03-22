package p005b.p293n.p294a;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import java.util.ArrayList;
import java.util.List;

/* renamed from: b.n.a.k0 */
/* loaded from: classes2.dex */
public final class C2657k0 {

    /* renamed from: a */
    public static InterfaceC2656k f7259a;

    /* renamed from: b */
    public static Boolean f7260b;

    /* renamed from: c */
    @NonNull
    public final List<String> f7261c = new ArrayList();

    /* renamed from: d */
    @Nullable
    public final Context f7262d;

    /* renamed from: e */
    @Nullable
    public InterfaceC2656k f7263e;

    /* renamed from: f */
    @Nullable
    public Boolean f7264f;

    public C2657k0(@Nullable Context context) {
        this.f7262d = context;
    }

    /* renamed from: c */
    public static void m3154c(@NonNull Fragment fragment, @NonNull List<String> list) {
        FragmentActivity activity = fragment.getActivity();
        if (activity == null) {
            return;
        }
        if (list.isEmpty()) {
            C2650h.m3150m(new C2664r(fragment, null), C2650h.m3142e(activity));
        } else {
            C2650h.m3151n(new C2664r(fragment, null), C2665s.m3160b(activity, list), 1025);
        }
    }

    /* renamed from: a */
    public C2657k0 m3155a(@Nullable String str) {
        if (C2645e0.m3119e(this.f7261c, str)) {
            return this;
        }
        this.f7261c.add(str);
        return this;
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x0096 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0097  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m3156b(@androidx.annotation.Nullable p005b.p293n.p294a.InterfaceC2652i r28) {
        /*
            Method dump skipped, instructions count: 1879
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p293n.p294a.C2657k0.m3156b(b.n.a.i):void");
    }
}
