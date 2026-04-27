package com.ta.utdid2.a.a;

/* JADX INFO: loaded from: classes3.dex */
public class h {
    public static String get(String key, String defaultValue) {
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            return (String) cls.getMethod("get", String.class, String.class).invoke(cls, key, defaultValue);
        } catch (Exception e) {
            return defaultValue;
        }
    }
}
