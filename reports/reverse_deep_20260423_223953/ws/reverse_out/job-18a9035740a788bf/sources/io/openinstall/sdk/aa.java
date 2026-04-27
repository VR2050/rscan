package io.openinstall.sdk;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.text.TextUtils;

/* JADX INFO: loaded from: classes3.dex */
public class aa {
    public static z a(Context context) {
        String lowerCase = Build.MANUFACTURER.toLowerCase();
        if (lowerCase.equals("huawei") || lowerCase.equals("tianyi")) {
            return new ae();
        }
        if (lowerCase.equals("honor")) {
            return ad.b(context) ? new ad() : new ae();
        }
        if (lowerCase.equals("xiaomi") || lowerCase.equals("redmi") || lowerCase.equals("blackshark") || lowerCase.equals("meitu")) {
            return new al();
        }
        if (lowerCase.equals("vivo")) {
            return new ak();
        }
        if (lowerCase.equals("oppo") || lowerCase.equals("realme") || lowerCase.equals("oneplus")) {
            return new ai(context);
        }
        if (lowerCase.equals("lenovo") || lowerCase.equals("motorola") || lowerCase.equals("zuk") || lowerCase.equals("motolora")) {
            return new af();
        }
        if (lowerCase.equals("samsung")) {
            return new aj();
        }
        if (lowerCase.equals("meizu") || lowerCase.equals("mblu")) {
            return new ag();
        }
        if (lowerCase.equals("nubia")) {
            return new ah();
        }
        if (lowerCase.equals("zte")) {
            return new am();
        }
        if (lowerCase.equals("asus")) {
            return new ab();
        }
        if (a(context, "com.coolpad.deviceidsupport")) {
            return new ac();
        }
        String strA = a("ro.build.freeme.label", "");
        if (strA != null && strA.equalsIgnoreCase("freemeos")) {
            return new am();
        }
        String strA2 = a("ro.ssui.product", "unknown");
        return (strA2 == null || strA2.equalsIgnoreCase("unknown")) ? (TextUtils.isEmpty(a("ro.build.version.emui", "")) && TextUtils.isEmpty(a("hw_sc.build.platform.version", ""))) ? !TextUtils.isEmpty(a("ro.build.version.magic", "")) ? ad.b(context) ? new ad() : new ae() : !TextUtils.isEmpty(a("ro.miui.ui.version.name", "")) ? new al() : !TextUtils.isEmpty(a("ro.vivo.os.version", "")) ? new ak() : !TextUtils.isEmpty(a("ro.build.version.opporom", "")) ? new ai(context) : new w() : new ae() : new am();
    }

    public static String a(String str, String str2) {
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            return (String) cls.getMethod("get", String.class, String.class).invoke(cls, str, str2);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static boolean a(Context context, String str) {
        try {
            context.getPackageManager().getPackageInfo(str, 1);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return false;
        }
    }
}
