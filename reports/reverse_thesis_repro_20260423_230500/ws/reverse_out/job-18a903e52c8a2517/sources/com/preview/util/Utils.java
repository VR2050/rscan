package com.preview.util;

import android.content.Context;
import android.util.TypedValue;

/* JADX INFO: loaded from: classes2.dex */
public class Utils {
    public static int dp2px(Context context, int dipValue) {
        return (int) TypedValue.applyDimension(1, dipValue, context.getResources().getDisplayMetrics());
    }

    public static int getStatusBarHeight(Context context) {
        int resourceId = context.getResources().getIdentifier("status_bar_height", "dimen", "android");
        if (resourceId <= 0) {
            return 0;
        }
        int result = context.getResources().getDimensionPixelSize(resourceId);
        return result;
    }
}
