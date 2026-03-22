package com.luck.picture.lib.tools;

/* loaded from: classes2.dex */
public class ValueOf {
    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: to */
    public static <T> T m4556to(Object obj, T t) {
        return obj == 0 ? t : obj;
    }

    public static boolean toBoolean(Object obj) {
        return toBoolean(obj, false);
    }

    public static double toDouble(Object obj) {
        return toDouble(obj, 0);
    }

    public static float toFloat(Object obj, long j2) {
        if (obj == null) {
            return j2;
        }
        try {
            return Float.valueOf(obj.toString().trim()).floatValue();
        } catch (Exception unused) {
            return j2;
        }
    }

    public static int toInt(Object obj, int i2) {
        if (obj == null) {
            return i2;
        }
        try {
            String trim = obj.toString().trim();
            return trim.contains(".") ? Integer.valueOf(trim.substring(0, trim.lastIndexOf("."))).intValue() : Integer.valueOf(trim).intValue();
        } catch (Exception unused) {
            return i2;
        }
    }

    public static long toLong(Object obj, long j2) {
        if (obj == null) {
            return j2;
        }
        try {
            String trim = obj.toString().trim();
            return trim.contains(".") ? Long.valueOf(trim.substring(0, trim.lastIndexOf("."))).longValue() : Long.valueOf(trim).longValue();
        } catch (Exception unused) {
            return j2;
        }
    }

    public static String toString(Object obj) {
        try {
            return obj.toString();
        } catch (Exception unused) {
            return "";
        }
    }

    public static boolean toBoolean(Object obj, boolean z) {
        if (obj == null) {
            return false;
        }
        try {
            return !"false".equals(obj.toString().trim().trim());
        } catch (Exception unused) {
            return z;
        }
    }

    public static double toDouble(Object obj, int i2) {
        if (obj == null) {
            return i2;
        }
        try {
            return Double.valueOf(obj.toString().trim()).doubleValue();
        } catch (Exception unused) {
            return i2;
        }
    }

    public static float toFloat(Object obj) {
        return toFloat(obj, 0L);
    }

    public static int toInt(Object obj) {
        return toInt(obj, 0);
    }

    public static long toLong(Object obj) {
        return toLong(obj, 0L);
    }
}
