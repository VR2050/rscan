package com.gyf.barlibrary;

import android.text.TextUtils;
import java.lang.reflect.Method;
import org.webrtc.utils.RecvStatsLogKey;

/* JADX INFO: loaded from: classes.dex */
public class OSUtils {
    private static final String KEY_DISPLAY = "ro.build.display.id";
    private static final String KEY_EMUI_VERSION_NAME = "ro.build.version.emui";
    private static final String KEY_MIUI_VERSION_NAME = "ro.miui.ui.version.name";

    public static boolean isMIUI() {
        String property = getSystemProperty(KEY_MIUI_VERSION_NAME, "");
        return !TextUtils.isEmpty(property);
    }

    public static boolean isMIUI6Later() {
        String version = getMIUIVersion();
        if (version.isEmpty()) {
            return false;
        }
        try {
            int num = Integer.valueOf(version.substring(1)).intValue();
            return num >= 6;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static String getMIUIVersion() {
        return isMIUI() ? getSystemProperty(KEY_MIUI_VERSION_NAME, "") : "";
    }

    public static boolean isEMUI() {
        String property = getSystemProperty(KEY_EMUI_VERSION_NAME, "");
        return !TextUtils.isEmpty(property);
    }

    public static String getEMUIVersion() {
        return isEMUI() ? getSystemProperty(KEY_EMUI_VERSION_NAME, "") : "";
    }

    public static boolean isEMUI3_1() {
        String property = getEMUIVersion();
        if ("EmotionUI 3".equals(property) || property.contains("EmotionUI_3.1")) {
            return true;
        }
        return false;
    }

    public static boolean isEMUI3_0() {
        String property = getEMUIVersion();
        if (property.contains("EmotionUI_3.0")) {
            return true;
        }
        return false;
    }

    public static boolean isFlymeOS() {
        return getFlymeOSFlag().toLowerCase().contains("flyme");
    }

    public static boolean isFlymeOS4Later() {
        int num;
        String version = getFlymeOSVersion();
        if (version.isEmpty()) {
            return false;
        }
        try {
            if (version.toLowerCase().contains(RecvStatsLogKey.KEY_OS)) {
                num = Integer.valueOf(version.substring(9, 10)).intValue();
            } else {
                num = Integer.valueOf(version.substring(6, 7)).intValue();
            }
            return num >= 4;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static boolean isFlymeOS5() {
        int num;
        String version = getFlymeOSVersion();
        if (version.isEmpty()) {
            return false;
        }
        try {
            if (version.toLowerCase().contains(RecvStatsLogKey.KEY_OS)) {
                num = Integer.valueOf(version.substring(9, 10)).intValue();
            } else {
                num = Integer.valueOf(version.substring(6, 7)).intValue();
            }
            return num == 5;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static String getFlymeOSVersion() {
        return isFlymeOS() ? getSystemProperty(KEY_DISPLAY, "") : "";
    }

    private static String getFlymeOSFlag() {
        return getSystemProperty(KEY_DISPLAY, "");
    }

    private static String getSystemProperty(String key, String defaultValue) {
        try {
            Class<?> clz = Class.forName("android.os.SystemProperties");
            Method get = clz.getMethod("get", String.class, String.class);
            return (String) get.invoke(clz, key, defaultValue);
        } catch (Exception e) {
            e.printStackTrace();
            return defaultValue;
        }
    }
}
