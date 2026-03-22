package com.yalantis.ucrop.util;

import android.os.Build;

/* loaded from: classes2.dex */
public class SdkUtils {
    public static boolean isQ() {
        return Build.VERSION.SDK_INT >= 29;
    }
}
