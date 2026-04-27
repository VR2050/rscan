package com.ta.utdid2.a.a;

import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes3.dex */
public class g {
    private static final Pattern a = Pattern.compile("([\t\r\n])+");

    /* JADX INFO: renamed from: a, reason: collision with other method in class */
    public static boolean m17a(String str) {
        if (str != null && str.length() > 0) {
            return false;
        }
        return true;
    }

    public static int a(String str) {
        if (str.length() <= 0) {
            return 0;
        }
        int i = 0;
        for (char c : str.toCharArray()) {
            i = (i * 31) + c;
        }
        return i;
    }
}
