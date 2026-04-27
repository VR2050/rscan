package org.webrtc.mozi.utils;

import android.text.TextUtils;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class StringUtils {
    public static String safeGet(String str) {
        return str == null ? "" : str;
    }

    public static String join(String separator, List<String> stringList) {
        if (CollectionUtils.isEmpty(stringList)) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        boolean needSeparator = false;
        for (String str : stringList) {
            if (needSeparator && separator != null) {
                builder.append(separator);
            }
            builder.append(str);
            needSeparator = true;
        }
        return builder.toString();
    }

    public static String join(String separator, String[] stringList) {
        if (stringList == null || stringList.length == 0) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        boolean needSeparator = false;
        for (String str : stringList) {
            if (needSeparator && separator != null) {
                builder.append(separator);
            }
            builder.append(str);
            needSeparator = true;
        }
        return builder.toString();
    }

    public static String getAppendString(String... list) {
        if (list == null || list.length == 0) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (String str : list) {
            builder.append(str);
        }
        return builder.toString();
    }

    public static boolean isNotEqualOrEmpty(String s1, String s2) {
        return (TextUtils.isEmpty(s1) || TextUtils.isEmpty(s2) || TextUtils.equals(s1, s2)) ? false : true;
    }

    public static String getFileBaseName(String fileName) {
        if (fileName == null) {
            return null;
        }
        int dotIndex = fileName.indexOf(".");
        if (dotIndex < 0) {
            return fileName;
        }
        return fileName.substring(0, dotIndex);
    }

    public static boolean equals(String s1, String s2) {
        if (s1 == s2) {
            return true;
        }
        return (s1 == null || s2 == null || !s1.equals(s2)) ? false : true;
    }

    public static boolean equalsIgnoreCase(String s1, String s2) {
        if (s1 == s2) {
            return true;
        }
        return (s1 == null || s2 == null || !s1.equalsIgnoreCase(s2)) ? false : true;
    }

    public static boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }

    public static boolean arrayEquals(String[] s1, String[] s2) {
        if (s1 == s2) {
            return true;
        }
        if (s1 == null || s2 == null || s1.length != s2.length) {
            return false;
        }
        int length = s1.length;
        for (int i = 0; i < length; i++) {
            if (!equals(s1[i], s2[i])) {
                return false;
            }
        }
        return true;
    }

    public static String appendThreadInfo(String content) {
        return getAppendString(content, ", thread = [", Thread.currentThread().toString(), "]");
    }
}
