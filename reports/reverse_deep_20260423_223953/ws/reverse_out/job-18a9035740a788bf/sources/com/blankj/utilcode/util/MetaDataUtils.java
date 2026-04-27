package com.blankj.utilcode.util;

import android.app.Activity;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;

/* JADX INFO: loaded from: classes.dex */
public final class MetaDataUtils {
    private MetaDataUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    public static String getMetaDataInApp(String key) {
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        PackageManager pm = Utils.getApp().getPackageManager();
        String packageName = Utils.getApp().getPackageName();
        try {
            ApplicationInfo ai = pm.getApplicationInfo(packageName, 128);
            String value = String.valueOf(ai.metaData.get(key));
            return value;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String getMetaDataInActivity(Activity activity, String key) {
        if (activity == null) {
            throw new NullPointerException("Argument 'activity' of type Activity (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getMetaDataInActivity((Class<? extends Activity>) activity.getClass(), key);
    }

    public static String getMetaDataInActivity(Class<? extends Activity> clz, String key) {
        if (clz == null) {
            throw new NullPointerException("Argument 'clz' of type Class<? extends Activity> (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        PackageManager pm = Utils.getApp().getPackageManager();
        ComponentName componentName = new ComponentName(Utils.getApp(), clz);
        try {
            ActivityInfo ai = pm.getActivityInfo(componentName, 128);
            String value = String.valueOf(ai.metaData.get(key));
            return value;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String getMetaDataInService(Service service, String key) {
        if (service == null) {
            throw new NullPointerException("Argument 'service' of type Service (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getMetaDataInService((Class<? extends Service>) service.getClass(), key);
    }

    public static String getMetaDataInService(Class<? extends Service> clz, String key) {
        if (clz == null) {
            throw new NullPointerException("Argument 'clz' of type Class<? extends Service> (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        PackageManager pm = Utils.getApp().getPackageManager();
        ComponentName componentName = new ComponentName(Utils.getApp(), clz);
        try {
            ServiceInfo info = pm.getServiceInfo(componentName, 128);
            String value = String.valueOf(info.metaData.get(key));
            return value;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String getMetaDataInReceiver(BroadcastReceiver receiver, String key) {
        if (receiver == null) {
            throw new NullPointerException("Argument 'receiver' of type BroadcastReceiver (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return getMetaDataInReceiver(receiver, key);
    }

    public static String getMetaDataInReceiver(Class<? extends BroadcastReceiver> clz, String key) {
        if (clz == null) {
            throw new NullPointerException("Argument 'clz' of type Class<? extends BroadcastReceiver> (#0 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (key == null) {
            throw new NullPointerException("Argument 'key' of type String (#1 out of 2, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        PackageManager pm = Utils.getApp().getPackageManager();
        ComponentName componentName = new ComponentName(Utils.getApp(), clz);
        try {
            ActivityInfo info = pm.getReceiverInfo(componentName, 128);
            String value = String.valueOf(info.metaData.get(key));
            return value;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return "";
        }
    }
}
