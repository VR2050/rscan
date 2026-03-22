package com.luck.picture.lib.tools;

import android.content.Context;
import android.widget.Toast;

/* loaded from: classes2.dex */
public final class ToastUtils {
    private static final long TIME = 1500;
    private static long lastToastTime;

    public static boolean isShowToast() {
        long currentTimeMillis = System.currentTimeMillis();
        if (currentTimeMillis - lastToastTime < TIME) {
            return true;
        }
        lastToastTime = currentTimeMillis;
        return false;
    }

    /* renamed from: s */
    public static void m4555s(Context context, String str) {
        if (isShowToast()) {
            return;
        }
        Toast.makeText(context.getApplicationContext(), str, 0).show();
    }
}
