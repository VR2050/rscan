package com.shuyu.gsyvideoplayer.utils;

import android.content.Context;
import android.os.Environment;
import java.io.File;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class StorageUtils {
    private static final String INDIVIDUAL_DIR_NAME = "video-cache";

    private static File getCacheDirectory(Context context, boolean z) {
        String str;
        try {
            str = Environment.getExternalStorageState();
        } catch (NullPointerException unused) {
            str = "";
        }
        File externalCacheDir = (z && "mounted".equals(str)) ? getExternalCacheDir(context) : null;
        if (externalCacheDir == null) {
            externalCacheDir = context.getCacheDir();
        }
        if (externalCacheDir != null) {
            return externalCacheDir;
        }
        StringBuilder m586H = C1499a.m586H("/data/data/");
        m586H.append(context.getPackageName());
        m586H.append("/cache/");
        return new File(m586H.toString());
    }

    private static File getExternalCacheDir(Context context) {
        File file = new File(new File(new File(new File(Environment.getExternalStorageDirectory(), "Android"), "data"), context.getPackageName()), "cache");
        if (file.exists() || file.mkdirs()) {
            return file;
        }
        return null;
    }

    public static File getIndividualCacheDirectory(Context context) {
        return new File(getCacheDirectory(context, true), INDIVIDUAL_DIR_NAME);
    }
}
