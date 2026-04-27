package com.blankj.utilcode.util;

import java.util.Map;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public final class SPStaticUtils {
    private static SPUtils sDefaultSPUtils;

    public static void setDefaultSPUtils(SPUtils spUtils) {
        sDefaultSPUtils = spUtils;
    }

    public static void put(String key, String value) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, getDefaultSPUtils());
    }

    public static void put(String key, String value, boolean isCommit) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, isCommit, getDefaultSPUtils());
    }

    public static String getString(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getString(key, getDefaultSPUtils());
    }

    public static String getString(String key, String defaultValue) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getString(key, defaultValue, getDefaultSPUtils());
    }

    public static void put(String key, int value) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, getDefaultSPUtils());
    }

    public static void put(String key, int value, boolean isCommit) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, isCommit, getDefaultSPUtils());
    }

    public static int getInt(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getInt(key, getDefaultSPUtils());
    }

    public static int getInt(String key, int defaultValue) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getInt(key, defaultValue, getDefaultSPUtils());
    }

    public static void put(String key, long value) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, getDefaultSPUtils());
    }

    public static void put(String key, long value, boolean isCommit) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, isCommit, getDefaultSPUtils());
    }

    public static long getLong(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getLong(key, getDefaultSPUtils());
    }

    public static long getLong(String key, long defaultValue) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getLong(key, defaultValue, getDefaultSPUtils());
    }

    public static void put(String key, float value) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, getDefaultSPUtils());
    }

    public static void put(String key, float value, boolean isCommit) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, isCommit, getDefaultSPUtils());
    }

    public static float getFloat(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getFloat(key, getDefaultSPUtils());
    }

    public static float getFloat(String key, float defaultValue) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getFloat(key, defaultValue, getDefaultSPUtils());
    }

    public static void put(String key, boolean value) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, getDefaultSPUtils());
    }

    public static void put(String key, boolean value, boolean isCommit) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, isCommit, getDefaultSPUtils());
    }

    public static boolean getBoolean(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getBoolean(key, getDefaultSPUtils());
    }

    public static boolean getBoolean(String key, boolean defaultValue) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getBoolean(key, defaultValue, getDefaultSPUtils());
    }

    public static void put(String key, Set<String> value) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, getDefaultSPUtils());
    }

    public static void put(String key, Set<String> value, boolean isCommit) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        put(key, value, isCommit, getDefaultSPUtils());
    }

    public static Set<String> getStringSet(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getStringSet(key, getDefaultSPUtils());
    }

    public static Set<String> getStringSet(String key, Set<String> defaultValue) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getStringSet(key, defaultValue, getDefaultSPUtils());
    }

    public static Map<String, ?> getAll() {
        return getAll(getDefaultSPUtils());
    }

    public static boolean contains(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return contains(key, getDefaultSPUtils());
    }

    public static void remove(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        remove(key, getDefaultSPUtils());
    }

    public static void remove(String key, boolean isCommit) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        remove(key, isCommit, getDefaultSPUtils());
    }

    public static void clear() {
        clear(getDefaultSPUtils());
    }

    public static void clear(boolean isCommit) {
        clear(isCommit, getDefaultSPUtils());
    }

    public static void put(String key, String value, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value);
    }

    public static void put(String key, String value, boolean isCommit, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#3 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value, isCommit);
    }

    public static String getString(String key, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getString(key);
    }

    public static String getString(String key, String defaultValue, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getString(key, defaultValue);
    }

    public static void put(String key, int value, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value);
    }

    public static void put(String key, int value, boolean isCommit, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#3 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value, isCommit);
    }

    public static int getInt(String key, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getInt(key);
    }

    public static int getInt(String key, int defaultValue, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getInt(key, defaultValue);
    }

    public static void put(String key, long value, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value);
    }

    public static void put(String key, long value, boolean isCommit, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#3 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value, isCommit);
    }

    public static long getLong(String key, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getLong(key);
    }

    public static long getLong(String key, long defaultValue, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getLong(key, defaultValue);
    }

    public static void put(String key, float value, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value);
    }

    public static void put(String key, float value, boolean isCommit, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#3 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value, isCommit);
    }

    public static float getFloat(String key, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getFloat(key);
    }

    public static float getFloat(String key, float defaultValue, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getFloat(key, defaultValue);
    }

    public static void put(String key, boolean value, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value);
    }

    public static void put(String key, boolean value, boolean isCommit, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#3 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value, isCommit);
    }

    public static boolean getBoolean(String key, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getBoolean(key);
    }

    public static boolean getBoolean(String key, boolean defaultValue, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getBoolean(key, defaultValue);
    }

    public static void put(String key, Set<String> value, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value);
    }

    public static void put(String key, Set<String> value, boolean isCommit, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#3 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.put(key, value, isCommit);
    }

    public static Set<String> getStringSet(String key, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getStringSet(key);
    }

    public static Set<String> getStringSet(String key, Set<String> defaultValue, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getStringSet(key, defaultValue);
    }

    public static Map<String, ?> getAll(SPUtils spUtils) {
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.getAll();
    }

    public static boolean contains(String key, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return spUtils.contains(key);
    }

    public static void remove(String key, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.remove(key);
    }

    public static void remove(String key, boolean isCommit, SPUtils spUtils) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#2 out of 3, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.remove(key, isCommit);
    }

    public static void clear(SPUtils spUtils) {
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.clear();
    }

    public static void clear(boolean isCommit, SPUtils spUtils) {
        if (spUtils == null) {
            throw new NullPointerException("Argument 'spUtils' of type SPUtils (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        spUtils.clear(isCommit);
    }

    private static SPUtils getDefaultSPUtils() {
        SPUtils sPUtils = sDefaultSPUtils;
        return sPUtils != null ? sPUtils : SPUtils.getInstance();
    }
}
