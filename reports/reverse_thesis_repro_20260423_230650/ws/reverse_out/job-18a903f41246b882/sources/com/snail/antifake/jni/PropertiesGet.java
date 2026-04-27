package com.snail.antifake.jni;

/* JADX INFO: loaded from: classes3.dex */
public class PropertiesGet {
    private static native String native_get(String str);

    private static native String native_get(String str, String str2);

    static {
        System.loadLibrary("property_get");
    }

    public static String getString(String key) {
        return native_get(key);
    }

    public static String getString(String key, String def) {
        return native_get(key, def);
    }
}
