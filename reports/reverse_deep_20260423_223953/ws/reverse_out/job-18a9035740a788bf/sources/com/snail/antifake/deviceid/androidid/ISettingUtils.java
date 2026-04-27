package com.snail.antifake.deviceid.androidid;

import android.content.ContentResolver;
import android.content.Context;
import android.os.IBinder;
import android.os.Process;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;

/* JADX INFO: loaded from: classes3.dex */
public class ISettingUtils {
    public static String getAndroidProperty(Context context, String name) {
        try {
            Method getUserId = Class.forName("android.os.UserHandle").getDeclaredMethod("getUserId", Integer.TYPE);
            getUserId.setAccessible(true);
            int uid = ((Integer) getUserId.invoke(null, Integer.valueOf(Process.myUid()))).intValue();
            Method getString = Class.forName("android.provider.Settings$Secure").getDeclaredMethod("getStringForUser", ContentResolver.class, String.class, Integer.TYPE);
            getString.setAccessible(true);
            return (String) getString.invoke(null, context.getContentResolver(), name, Integer.valueOf(uid));
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String getAndroidPropertyLevel1(Context context, String name) {
        ContentResolver resolver = context.getContentResolver();
        try {
            Method getUserId = Class.forName("android.os.UserHandle").getDeclaredMethod("getUserId", Integer.TYPE);
            getUserId.setAccessible(true);
            int uid = ((Integer) getUserId.invoke(null, Integer.valueOf(Process.myUid()))).intValue();
            HashSet<String> MOVED_TO_SECURE = new HashSet<>();
            HashSet<String> MOVED_TO_LOCK_SETTINGS = new HashSet<>();
            HashSet<String> MOVED_TO_GLOBAL = new HashSet<>();
            try {
                Class<?> cls = Class.forName("android.provider.Settings$Global");
                Field field = cls.getDeclaredField("MOVED_TO_SECURE");
                field.setAccessible(true);
                MOVED_TO_SECURE = (HashSet) field.get(cls);
            } catch (Exception e) {
            }
            try {
                Class<?> cls2 = Class.forName("android.provider.Settings$Secure");
                Field field2 = cls2.getDeclaredField("MOVED_TO_LOCK_SETTINGS");
                field2.setAccessible(true);
                MOVED_TO_LOCK_SETTINGS = (HashSet) field2.get(cls2);
            } catch (Exception e2) {
            }
            try {
                Class<?> cls3 = Class.forName("android.provider.Settings$Secure");
                Field field3 = cls3.getDeclaredField("MOVED_TO_GLOBAL");
                field3.setAccessible(true);
                MOVED_TO_GLOBAL = (HashSet) field3.get(cls3);
            } catch (Exception e3) {
            }
            if (!MOVED_TO_SECURE.contains(name)) {
                if (MOVED_TO_GLOBAL.contains(name)) {
                    Method getStringForUser = Class.forName("android.provider.Global").getDeclaredMethod("getStringForUser", ContentResolver.class, String.class, Integer.TYPE);
                    getStringForUser.setAccessible(true);
                    return (String) getStringForUser.invoke(null, resolver, name, Integer.valueOf(uid));
                }
                if (MOVED_TO_LOCK_SETTINGS.contains(name)) {
                    Method getService = Class.forName("android.os.ServiceManager").getDeclaredMethod("getService", new Class[0]);
                    getService.setAccessible(true);
                    IBinder binder = (IBinder) getService.invoke(null, "lock_settings");
                    Method asInterface = Class.forName("com.android.internal.widget.ILockSettings$Stub").getDeclaredMethod("asInterface", IBinder.class);
                    asInterface.setAccessible(true);
                    Object binderProxy = asInterface.invoke(null, binder);
                    boolean sIsSystemProcess = Process.myUid() == 1000;
                    if (MOVED_TO_LOCK_SETTINGS.contains(name) && binderProxy != null && !sIsSystemProcess) {
                        Method getString = binderProxy.getClass().getDeclaredMethod("getString", String.class, String.class, Integer.TYPE);
                        return (String) getString.invoke(name, "0", Integer.valueOf(uid));
                    }
                }
            }
            Field field4 = Class.forName("android.provider.Settings$Secure").getDeclaredField("sNameValueCache");
            field4.setAccessible(true);
            Object sNameValueCache = field4.get(null);
            return (String) sNameValueCache.getClass().getDeclaredMethod("getStringForUser", ContentResolver.class, String.class, Integer.TYPE).invoke(sNameValueCache, resolver, name, Integer.valueOf(uid));
        } catch (Exception e4) {
            e4.printStackTrace();
            return "";
        }
    }
}
