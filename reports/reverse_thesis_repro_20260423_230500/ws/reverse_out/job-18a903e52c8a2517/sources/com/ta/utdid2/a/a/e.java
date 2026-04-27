package com.ta.utdid2.a.a;

import android.content.Context;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import java.util.Random;

/* JADX INFO: loaded from: classes3.dex */
public class e {
    public static String a() {
        int iCurrentTimeMillis = (int) (System.currentTimeMillis() / 1000);
        int iNanoTime = (int) System.nanoTime();
        int iNextInt = new Random().nextInt();
        int iNextInt2 = new Random().nextInt();
        byte[] bytes = d.getBytes(iCurrentTimeMillis);
        byte[] bytes2 = d.getBytes(iNanoTime);
        byte[] bytes3 = d.getBytes(iNextInt);
        byte[] bytes4 = d.getBytes(iNextInt2);
        byte[] bArr = new byte[16];
        System.arraycopy(bytes, 0, bArr, 0, 4);
        System.arraycopy(bytes2, 0, bArr, 4, 4);
        System.arraycopy(bytes3, 0, bArr, 8, 4);
        System.arraycopy(bytes4, 0, bArr, 12, 4);
        return b.encodeToString(bArr, 2);
    }

    public static String a(Context context) {
        String strB = null;
        if (!c.a() && context != null) {
            try {
                TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
                if (telephonyManager != null) {
                    strB = telephonyManager.getDeviceId();
                }
            } catch (Exception e) {
            }
        }
        if (g.m17a(strB)) {
            strB = b();
        }
        if (g.m17a(strB)) {
            strB = b(context);
        }
        if (g.m17a(strB)) {
            return a();
        }
        return strB;
    }

    private static String b(Context context) {
        String string;
        String str = "";
        try {
            string = Settings.Secure.getString(context.getContentResolver(), "android_id");
        } catch (Throwable th) {
        }
        try {
            if (!TextUtils.isEmpty(string) && !string.equalsIgnoreCase("a5f5faddde9e9f02") && !string.equalsIgnoreCase("8e17f7422b35fbea")) {
                if (!string.equalsIgnoreCase("0000000000000000")) {
                    return string;
                }
            }
            return "";
        } catch (Throwable th2) {
            str = string;
            return str;
        }
    }

    private static String b() {
        String str = h.get("ro.aliyun.clouduuid", "");
        if (TextUtils.isEmpty(str)) {
            str = h.get("ro.sys.aliyun.clouduuid", "");
        }
        if (TextUtils.isEmpty(str)) {
            return c();
        }
        return str;
    }

    private static String c() {
        try {
            return (String) Class.forName("com.yunos.baseservice.clouduuid.CloudUUID").getMethod("getCloudUUID", new Class[0]).invoke(null, new Object[0]);
        } catch (Exception e) {
            return "";
        }
    }

    public static String c(Context context) {
        String subscriberId = null;
        if (context != null) {
            try {
                TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
                if (telephonyManager != null) {
                    subscriberId = telephonyManager.getSubscriberId();
                }
            } catch (Exception e) {
            }
        }
        if (g.m17a(subscriberId)) {
            return a();
        }
        return subscriberId;
    }
}
