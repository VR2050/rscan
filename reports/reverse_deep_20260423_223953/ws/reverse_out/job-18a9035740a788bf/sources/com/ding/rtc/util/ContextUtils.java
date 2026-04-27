package com.ding.rtc.util;

import android.content.Context;

/* JADX INFO: loaded from: classes.dex */
public class ContextUtils {
    public static String getExternalFilesDir(String dir) {
        Context context = org.webrtc.mozi.ContextUtils.getApplicationContext();
        return context != null ? context.getExternalFilesDir(dir).getAbsolutePath() : "";
    }
}
