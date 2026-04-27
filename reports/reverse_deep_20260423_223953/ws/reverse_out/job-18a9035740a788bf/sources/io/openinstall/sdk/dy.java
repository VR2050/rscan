package io.openinstall.sdk;

import android.text.TextUtils;

/* JADX INFO: loaded from: classes3.dex */
public class dy {
    public static void a(String str) {
        if (ec.a && !TextUtils.isEmpty(str)) {
            int length = str.length();
            if (length < 10) {
                e("serialNumber");
                return;
            }
            for (int i = 0; i < length; i++) {
                char cCharAt = str.charAt(i);
                if (!Character.isDigit(cCharAt) && !Character.isLetter(cCharAt)) {
                    e("serialNumber");
                    return;
                }
            }
        }
    }

    public static void b(String str) {
        if (ec.a && !TextUtils.isEmpty(str)) {
            int length = str.length();
            if (length != 16 && length != 32) {
                e("android_id");
                return;
            }
            for (int i = 0; i < length; i++) {
                char cCharAt = str.charAt(i);
                if (!Character.isDigit(cCharAt) && !Character.isLetter(cCharAt)) {
                    e("android_id");
                    return;
                }
            }
        }
    }

    public static void c(String str) {
        if (ec.a && !TextUtils.isEmpty(str)) {
            int length = str.length();
            if (length != 12 && length != 32 && length != 36 && length != 64) {
                f("oaid");
                return;
            }
            for (int i = 0; i < length; i++) {
                char cCharAt = str.charAt(i);
                if (!Character.isDigit(cCharAt) && !Character.isLetter(cCharAt) && cCharAt != '-') {
                    f("oaid");
                    return;
                }
            }
        }
    }

    public static void d(String str) {
        if (ec.a && !TextUtils.isEmpty(str)) {
            int length = str.length();
            if (length != 32 && length != 36) {
                f("gaid");
            }
            for (int i = 0; i < length; i++) {
                char cCharAt = str.charAt(i);
                if (!Character.isDigit(cCharAt) && !Character.isLetter(cCharAt) && cCharAt != '-') {
                    f("gaid");
                    return;
                }
            }
        }
    }

    private static void e(String str) {
        ec.b("传入错误的 %s 将导致统计数据异常，请检查集成代码", str);
    }

    private static void f(String str) {
        ec.b("传入错误的 %s 将导致广告匹配失败，请检查集成代码", str);
    }
}
