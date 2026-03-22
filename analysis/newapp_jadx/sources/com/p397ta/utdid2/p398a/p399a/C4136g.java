package com.p397ta.utdid2.p398a.p399a;

import java.util.regex.Pattern;

/* renamed from: com.ta.utdid2.a.a.g */
/* loaded from: classes2.dex */
public class C4136g {

    /* renamed from: a */
    private static final Pattern f10809a = Pattern.compile("([\t\r\n])+");

    /* renamed from: a */
    public static boolean m4661a(String str) {
        return str == null || str.length() <= 0;
    }

    /* renamed from: a */
    public static int m4660a(String str) {
        if (str.length() <= 0) {
            return 0;
        }
        int i2 = 0;
        for (char c2 : str.toCharArray()) {
            i2 = (i2 * 31) + c2;
        }
        return i2;
    }
}
