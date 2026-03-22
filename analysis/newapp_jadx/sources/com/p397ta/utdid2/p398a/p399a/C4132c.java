package com.p397ta.utdid2.p398a.p399a;

import android.os.Build;

/* renamed from: com.ta.utdid2.a.a.c */
/* loaded from: classes2.dex */
public class C4132c {
    /* renamed from: a */
    public static boolean m4650a() {
        if (Build.VERSION.SDK_INT >= 29) {
            return true;
        }
        String str = Build.VERSION.CODENAME;
        return str.length() == 1 && str.charAt(0) >= 'Q' && str.charAt(0) <= 'Z';
    }
}
