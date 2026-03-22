package com.luck.picture.lib.tools;

import android.os.Build;

/* loaded from: classes2.dex */
public class SdkVersionUtils {
    public static boolean checkedAndroid_Q() {
        return Build.VERSION.SDK_INT >= 29;
    }

    public static boolean checkedAndroid_R() {
        return Build.VERSION.SDK_INT >= 30;
    }
}
