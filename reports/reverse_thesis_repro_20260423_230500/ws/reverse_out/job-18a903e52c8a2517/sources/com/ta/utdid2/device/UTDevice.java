package com.ta.utdid2.device;

import android.content.Context;
import com.ta.utdid2.a.a.g;

/* JADX INFO: loaded from: classes3.dex */
public class UTDevice {
    @Deprecated
    public static String getUtdid(Context context) {
        return d(context);
    }

    @Deprecated
    public static String getUtdidForUpdate(Context context) {
        return e(context);
    }

    private static String d(Context context) {
        a aVarB = b.b(context);
        if (aVarB == null || g.m17a(aVarB.f())) {
            return "ffffffffffffffffffffffff";
        }
        return aVarB.f();
    }

    private static String e(Context context) {
        String strH = c.a(context).h();
        return (strH == null || g.m17a(strH)) ? "ffffffffffffffffffffffff" : strH;
    }
}
