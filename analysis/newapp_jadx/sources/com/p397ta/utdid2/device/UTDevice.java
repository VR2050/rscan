package com.p397ta.utdid2.device;

import android.content.Context;
import com.p397ta.utdid2.p398a.p399a.C4136g;

/* loaded from: classes2.dex */
public class UTDevice {
    /* renamed from: d */
    private static String m4710d(Context context) {
        C4143a m4723b = C4144b.m4723b(context);
        return (m4723b == null || C4136g.m4661a(m4723b.m4720f())) ? "ffffffffffffffffffffffff" : m4723b.m4720f();
    }

    /* renamed from: e */
    private static String m4711e(Context context) {
        String m4736h = C4145c.m4724a(context).m4736h();
        return (m4736h == null || C4136g.m4661a(m4736h)) ? "ffffffffffffffffffffffff" : m4736h;
    }

    @Deprecated
    public static String getUtdid(Context context) {
        return m4710d(context);
    }

    @Deprecated
    public static String getUtdidForUpdate(Context context) {
        return m4711e(context);
    }
}
