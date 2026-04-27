package com.zhy.http.okhttp.utils;

import android.util.Log;

/* JADX INFO: loaded from: classes3.dex */
public class L {
    private static boolean debug = false;

    public static void e(String msg) {
        if (debug) {
            Log.e("OkHttp", msg);
        }
    }
}
