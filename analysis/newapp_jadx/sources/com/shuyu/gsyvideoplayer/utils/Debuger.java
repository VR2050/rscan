package com.shuyu.gsyvideoplayer.utils;

import android.app.Activity;
import android.text.TextUtils;
import android.widget.Toast;

/* loaded from: classes2.dex */
public class Debuger {
    public static boolean DEBUG_TAG = false;
    public static final String LOG_TAG = "GSYVideoPlayer";

    public static void Toast(Activity activity, String str) {
        if (!DEBUG_TAG || TextUtils.isEmpty(str)) {
            return;
        }
        Toast.makeText(activity, str, 0).show();
    }

    public static void disable() {
        DEBUG_TAG = false;
    }

    public static void enable() {
        DEBUG_TAG = true;
    }

    public static boolean getDebugMode() {
        return DEBUG_TAG;
    }

    public static void printfError(String str) {
        if (DEBUG_TAG) {
            TextUtils.isEmpty(str);
        }
    }

    public static void printfLog(String str, String str2) {
        if (!DEBUG_TAG || str2 == null) {
            return;
        }
        TextUtils.isEmpty(str2);
    }

    public static void printfWarning(String str, String str2) {
        if (!DEBUG_TAG || str2 == null) {
            return;
        }
        TextUtils.isEmpty(str2);
    }

    public static void printfError(String str, String str2) {
        if (DEBUG_TAG) {
            TextUtils.isEmpty(str2);
        }
    }

    public static void printfLog(String str) {
        printfLog(LOG_TAG, str);
    }

    public static void printfWarning(String str) {
        printfWarning(LOG_TAG, str);
    }

    public static void printfError(String str, Exception exc) {
        if (DEBUG_TAG) {
            TextUtils.isEmpty(str);
            exc.printStackTrace();
        }
    }
}
