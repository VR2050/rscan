package com.p397ta.utdid2.p398a.p399a;

import android.content.Context;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import java.util.Random;

/* renamed from: com.ta.utdid2.a.a.e */
/* loaded from: classes2.dex */
public class C4134e {
    /* renamed from: a */
    public static String m4651a() {
        int currentTimeMillis = (int) (System.currentTimeMillis() / 1000);
        int nanoTime = (int) System.nanoTime();
        int nextInt = new Random().nextInt();
        int nextInt2 = new Random().nextInt();
        byte[] bytes = C4133d.getBytes(currentTimeMillis);
        byte[] bytes2 = C4133d.getBytes(nanoTime);
        byte[] bytes3 = C4133d.getBytes(nextInt);
        byte[] bytes4 = C4133d.getBytes(nextInt2);
        byte[] bArr = new byte[16];
        System.arraycopy(bytes, 0, bArr, 0, 4);
        System.arraycopy(bytes2, 0, bArr, 4, 4);
        System.arraycopy(bytes3, 0, bArr, 8, 4);
        System.arraycopy(bytes4, 0, bArr, 12, 4);
        return C4131b.encodeToString(bArr, 2);
    }

    /* renamed from: b */
    private static String m4654b(Context context) {
        String str = "";
        try {
            String string = Settings.Secure.getString(context.getContentResolver(), "android_id");
            try {
                if (!TextUtils.isEmpty(string) && !string.equalsIgnoreCase("a5f5faddde9e9f02") && !string.equalsIgnoreCase("8e17f7422b35fbea")) {
                    if (!string.equalsIgnoreCase("0000000000000000")) {
                        return string;
                    }
                }
                return "";
            } catch (Throwable unused) {
                str = string;
                return str;
            }
        } catch (Throwable unused2) {
        }
    }

    /* renamed from: c */
    private static String m4655c() {
        try {
            return (String) Class.forName("com.yunos.baseservice.clouduuid.CloudUUID").getMethod("getCloudUUID", new Class[0]).invoke(null, new Object[0]);
        } catch (Exception unused) {
            return "";
        }
    }

    /* renamed from: c */
    public static String m4656c(Context context) {
        String str = null;
        if (context != null) {
            try {
                TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
                if (telephonyManager != null) {
                    str = telephonyManager.getSubscriberId();
                }
            } catch (Exception unused) {
            }
        }
        return C4136g.m4661a(str) ? m4651a() : str;
    }

    /* renamed from: b */
    private static String m4653b() {
        String str = C4137h.get("ro.aliyun.clouduuid", "");
        if (TextUtils.isEmpty(str)) {
            str = C4137h.get("ro.sys.aliyun.clouduuid", "");
        }
        return TextUtils.isEmpty(str) ? m4655c() : str;
    }

    /* renamed from: a */
    public static String m4652a(Context context) {
        String str = null;
        if (!C4132c.m4650a() && context != null) {
            try {
                TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
                if (telephonyManager != null) {
                    str = telephonyManager.getDeviceId();
                }
            } catch (Exception unused) {
            }
        }
        if (C4136g.m4661a(str)) {
            str = m4653b();
        }
        if (C4136g.m4661a(str)) {
            str = m4654b(context);
        }
        return C4136g.m4661a(str) ? m4651a() : str;
    }
}
