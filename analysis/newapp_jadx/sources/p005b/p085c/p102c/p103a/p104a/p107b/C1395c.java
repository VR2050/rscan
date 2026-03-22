package p005b.p085c.p102c.p103a.p104a.p107b;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import java.io.File;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.c.a.a.b.c */
/* loaded from: classes.dex */
public final class C1395c {
    /* renamed from: a */
    public static boolean m473a(Context context) {
        boolean z;
        int length;
        try {
            if (!Build.HARDWARE.contains("goldfish") && !Build.PRODUCT.contains("sdk") && !Build.FINGERPRINT.contains("generic")) {
                TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
                if (telephonyManager != null) {
                    String deviceId = telephonyManager.getDeviceId();
                    if (deviceId != null && (length = deviceId.length()) != 0) {
                        for (int i2 = 0; i2 < length; i2++) {
                            if (!Character.isWhitespace(deviceId.charAt(i2)) && deviceId.charAt(i2) != '0') {
                                z = false;
                                break;
                            }
                        }
                    }
                    z = true;
                    if (z) {
                        return true;
                    }
                }
                return C4195m.m4822o(Settings.Secure.getString(context.getContentResolver(), "android_id"));
            }
            return true;
        } catch (Exception unused) {
            return false;
        }
    }

    /* renamed from: b */
    public static boolean m474b() {
        String[] strArr = {"/system/bin/", "/system/xbin/", "/system/sbin/", "/sbin/", "/vendor/bin/"};
        for (int i2 = 0; i2 < 5; i2++) {
            try {
                if (new File(strArr[i2] + "su").exists()) {
                    return true;
                }
            } catch (Exception unused) {
            }
        }
        return false;
    }

    /* renamed from: c */
    public static String m475c() {
        try {
            return (String) Class.forName("android.os.SystemProperties").getMethod("get", String.class, String.class).invoke(null, "ro.kernel.qemu", "0");
        } catch (Exception unused) {
            return "0";
        }
    }
}
