package io.openinstall.sdk;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;

/* JADX INFO: loaded from: classes3.dex */
public class ea {
    private static Object a(Context context, String str) {
        try {
            Bundle bundle = context.getPackageManager().getApplicationInfo(context.getPackageName(), 128).metaData;
            if (bundle != null) {
                return bundle.get(str);
            }
            return null;
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        }
    }

    public static String a(Context context) {
        Object objA = a(context, "com.openinstall.APP_KEY");
        if (objA == null) {
            return "";
        }
        try {
            return String.valueOf(objA);
        } catch (Exception e) {
            return "";
        }
    }

    public static boolean b(Context context) {
        Object objA = a(context, "com.openinstall.PB_ENABLED");
        if (objA == null) {
            return true;
        }
        try {
            return Boolean.parseBoolean(String.valueOf(objA));
        } catch (Exception e) {
            return true;
        }
    }

    public static boolean c(Context context) {
        Object objA = a(context, "com.openinstall.PB_SIGNAL");
        if (objA == null) {
            return true;
        }
        try {
            return Boolean.parseBoolean(String.valueOf(objA));
        } catch (Exception e) {
            return true;
        }
    }

    public static boolean d(Context context) {
        Object objA = a(context, "com.openinstall.AD_TRACK");
        if (objA == null) {
            return false;
        }
        try {
            return Boolean.parseBoolean(String.valueOf(objA));
        } catch (Exception e) {
            return false;
        }
    }
}
