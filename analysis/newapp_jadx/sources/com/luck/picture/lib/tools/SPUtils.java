package com.luck.picture.lib.tools;

import android.app.Application;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public class SPUtils {
    private static final Map<String, SPUtils> SP_UTILS_MAP = new HashMap();

    /* renamed from: sp */
    private SharedPreferences f10213sp;

    private SPUtils(String str) {
        this.f10213sp = getApplicationByReflect().getSharedPreferences(str, 0);
    }

    private static Application getApplicationByReflect() {
        try {
            Class<?> cls = Class.forName("android.app.ActivityThread");
            Object invoke = cls.getMethod("getApplication", new Class[0]).invoke(cls.getMethod("currentActivityThread", new Class[0]).invoke(null, new Object[0]), new Object[0]);
            if (invoke != null) {
                return (Application) invoke;
            }
            throw new NullPointerException("u should init first");
        } catch (ClassNotFoundException e2) {
            e2.printStackTrace();
            throw new NullPointerException("u should init first");
        } catch (IllegalAccessException e3) {
            e3.printStackTrace();
            throw new NullPointerException("u should init first");
        } catch (NoSuchMethodException e4) {
            e4.printStackTrace();
            throw new NullPointerException("u should init first");
        } catch (InvocationTargetException e5) {
            e5.printStackTrace();
            throw new NullPointerException("u should init first");
        }
    }

    public static SPUtils getInstance() {
        return getInstance("", 0);
    }

    public static SPUtils getPictureSpUtils() {
        return getInstance("PictureSpUtils");
    }

    private static boolean isSpace(String str) {
        if (str == null) {
            return true;
        }
        int length = str.length();
        for (int i2 = 0; i2 < length; i2++) {
            if (!Character.isWhitespace(str.charAt(i2))) {
                return false;
            }
        }
        return true;
    }

    public void clear() {
        clear(false);
    }

    public boolean contains(@NonNull String str) {
        return this.f10213sp.contains(str);
    }

    public Map<String, ?> getAll() {
        return this.f10213sp.getAll();
    }

    public boolean getBoolean(@NonNull String str) {
        return getBoolean(str, false);
    }

    public float getFloat(@NonNull String str) {
        return getFloat(str, -1.0f);
    }

    public int getInt(@NonNull String str) {
        return getInt(str, -1);
    }

    public long getLong(@NonNull String str) {
        return getLong(str, -1L);
    }

    public String getString(@NonNull String str) {
        return getString(str, "");
    }

    public Set<String> getStringSet(@NonNull String str) {
        return getStringSet(str, Collections.emptySet());
    }

    public void put(@NonNull String str, String str2) {
        put(str, str2, false);
    }

    public void remove(@NonNull String str) {
        remove(str, false);
    }

    public static SPUtils getInstance(int i2) {
        return getInstance("", i2);
    }

    public void clear(boolean z) {
        if (z) {
            this.f10213sp.edit().clear().commit();
        } else {
            this.f10213sp.edit().clear().apply();
        }
    }

    public boolean getBoolean(@NonNull String str, boolean z) {
        return this.f10213sp.getBoolean(str, z);
    }

    public float getFloat(@NonNull String str, float f2) {
        return this.f10213sp.getFloat(str, f2);
    }

    public int getInt(@NonNull String str, int i2) {
        return this.f10213sp.getInt(str, i2);
    }

    public long getLong(@NonNull String str, long j2) {
        return this.f10213sp.getLong(str, j2);
    }

    public String getString(@NonNull String str, String str2) {
        return this.f10213sp.getString(str, str2);
    }

    public Set<String> getStringSet(@NonNull String str, Set<String> set) {
        return this.f10213sp.getStringSet(str, set);
    }

    public void put(@NonNull String str, String str2, boolean z) {
        if (z) {
            this.f10213sp.edit().putString(str, str2).commit();
        } else {
            this.f10213sp.edit().putString(str, str2).apply();
        }
    }

    public void remove(@NonNull String str, boolean z) {
        if (z) {
            this.f10213sp.edit().remove(str).commit();
        } else {
            this.f10213sp.edit().remove(str).apply();
        }
    }

    private SPUtils(String str, int i2) {
        this.f10213sp = getApplicationByReflect().getSharedPreferences(str, i2);
    }

    public static SPUtils getInstance(String str) {
        return getInstance(str, 0);
    }

    public static SPUtils getInstance(String str, int i2) {
        if (isSpace(str)) {
            str = "spUtils";
        }
        Map<String, SPUtils> map = SP_UTILS_MAP;
        SPUtils sPUtils = map.get(str);
        if (sPUtils == null) {
            synchronized (SPUtils.class) {
                sPUtils = map.get(str);
                if (sPUtils == null) {
                    sPUtils = new SPUtils(str, i2);
                    map.put(str, sPUtils);
                }
            }
        }
        return sPUtils;
    }

    public void put(@NonNull String str, int i2) {
        put(str, i2, false);
    }

    public void put(@NonNull String str, int i2, boolean z) {
        if (z) {
            this.f10213sp.edit().putInt(str, i2).commit();
        } else {
            this.f10213sp.edit().putInt(str, i2).apply();
        }
    }

    public void put(@NonNull String str, long j2) {
        put(str, j2, false);
    }

    public void put(@NonNull String str, long j2, boolean z) {
        if (z) {
            this.f10213sp.edit().putLong(str, j2).commit();
        } else {
            this.f10213sp.edit().putLong(str, j2).apply();
        }
    }

    public void put(@NonNull String str, float f2) {
        put(str, f2, false);
    }

    public void put(@NonNull String str, float f2, boolean z) {
        if (z) {
            this.f10213sp.edit().putFloat(str, f2).commit();
        } else {
            this.f10213sp.edit().putFloat(str, f2).apply();
        }
    }

    public void put(@NonNull String str, boolean z) {
        put(str, z, false);
    }

    public void put(@NonNull String str, boolean z, boolean z2) {
        if (z2) {
            this.f10213sp.edit().putBoolean(str, z).commit();
        } else {
            this.f10213sp.edit().putBoolean(str, z).apply();
        }
    }

    public void put(@NonNull String str, Set<String> set) {
        put(str, set, false);
    }

    public void put(@NonNull String str, Set<String> set, boolean z) {
        if (z) {
            this.f10213sp.edit().putStringSet(str, set).commit();
        } else {
            this.f10213sp.edit().putStringSet(str, set).apply();
        }
    }
}
