package com.blankj.utilcode.util;

import android.os.Build;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import java.util.Locale;

/* JADX INFO: loaded from: classes.dex */
public class ViewUtils {
    public static void setViewEnabled(View view, boolean enabled) {
        setViewEnabled(view, enabled, (View) null);
    }

    public static void setViewEnabled(View view, boolean enabled, View... excludes) {
        if (view == null) {
            return;
        }
        if (excludes != null) {
            for (View exclude : excludes) {
                if (view == exclude) {
                    return;
                }
            }
        }
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            int childCount = viewGroup.getChildCount();
            for (int i = 0; i < childCount; i++) {
                setViewEnabled(viewGroup.getChildAt(i), enabled, excludes);
            }
        }
        view.setEnabled(enabled);
    }

    public static void runOnUiThread(Runnable runnable) {
        Utils.runOnUiThread(runnable);
    }

    public static void runOnUiThreadDelayed(Runnable runnable, long delayMillis) {
        Utils.runOnUiThreadDelayed(runnable, delayMillis);
    }

    public static boolean isLayoutRtl() {
        Locale primaryLocale;
        if (Build.VERSION.SDK_INT < 17) {
            return false;
        }
        if (Build.VERSION.SDK_INT >= 24) {
            primaryLocale = Utils.getApp().getResources().getConfiguration().getLocales().get(0);
        } else {
            primaryLocale = Utils.getApp().getResources().getConfiguration().locale;
        }
        return TextUtils.getLayoutDirectionFromLocale(primaryLocale) == 1;
    }

    public static void fixScrollViewTopping(View view) {
        view.setFocusable(false);
        ViewGroup viewGroup = null;
        if (view instanceof ViewGroup) {
            viewGroup = (ViewGroup) view;
        }
        if (viewGroup == null) {
            return;
        }
        int n = viewGroup.getChildCount();
        for (int i = 0; i < n; i++) {
            View childAt = viewGroup.getChildAt(i);
            childAt.setFocusable(false);
            if (childAt instanceof ViewGroup) {
                fixScrollViewTopping(childAt);
            }
        }
    }
}
