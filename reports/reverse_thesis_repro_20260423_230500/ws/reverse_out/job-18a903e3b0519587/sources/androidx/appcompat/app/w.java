package androidx.appcompat.app;

import android.content.res.Resources;
import android.os.Build;
import android.util.Log;
import android.util.LongSparseArray;
import java.lang.reflect.Field;

/* JADX INFO: loaded from: classes.dex */
abstract class w {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static Field f3263a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static boolean f3264b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static Class f3265c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static boolean f3266d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static Field f3267e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static boolean f3268f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static Field f3269g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static boolean f3270h;

    static void a(Resources resources) {
        if (Build.VERSION.SDK_INT >= 28) {
            return;
        }
        b(resources);
    }

    private static void b(Resources resources) {
        Object obj;
        if (!f3270h) {
            try {
                Field declaredField = Resources.class.getDeclaredField("mResourcesImpl");
                f3269g = declaredField;
                declaredField.setAccessible(true);
            } catch (NoSuchFieldException e3) {
                Log.e("ResourcesFlusher", "Could not retrieve Resources#mResourcesImpl field", e3);
            }
            f3270h = true;
        }
        Field field = f3269g;
        if (field == null) {
            return;
        }
        Object obj2 = null;
        try {
            obj = field.get(resources);
        } catch (IllegalAccessException e4) {
            Log.e("ResourcesFlusher", "Could not retrieve value from Resources#mResourcesImpl", e4);
            obj = null;
        }
        if (obj == null) {
            return;
        }
        if (!f3264b) {
            try {
                Field declaredField2 = obj.getClass().getDeclaredField("mDrawableCache");
                f3263a = declaredField2;
                declaredField2.setAccessible(true);
            } catch (NoSuchFieldException e5) {
                Log.e("ResourcesFlusher", "Could not retrieve ResourcesImpl#mDrawableCache field", e5);
            }
            f3264b = true;
        }
        Field field2 = f3263a;
        if (field2 != null) {
            try {
                obj2 = field2.get(obj);
            } catch (IllegalAccessException e6) {
                Log.e("ResourcesFlusher", "Could not retrieve value from ResourcesImpl#mDrawableCache", e6);
            }
        }
        if (obj2 != null) {
            c(obj2);
        }
    }

    private static void c(Object obj) {
        LongSparseArray longSparseArray;
        if (!f3266d) {
            try {
                f3265c = Class.forName("android.content.res.ThemedResourceCache");
            } catch (ClassNotFoundException e3) {
                Log.e("ResourcesFlusher", "Could not find ThemedResourceCache class", e3);
            }
            f3266d = true;
        }
        Class cls = f3265c;
        if (cls == null) {
            return;
        }
        if (!f3268f) {
            try {
                Field declaredField = cls.getDeclaredField("mUnthemedEntries");
                f3267e = declaredField;
                declaredField.setAccessible(true);
            } catch (NoSuchFieldException e4) {
                Log.e("ResourcesFlusher", "Could not retrieve ThemedResourceCache#mUnthemedEntries field", e4);
            }
            f3268f = true;
        }
        Field field = f3267e;
        if (field == null) {
            return;
        }
        try {
            longSparseArray = (LongSparseArray) field.get(obj);
        } catch (IllegalAccessException e5) {
            Log.e("ResourcesFlusher", "Could not retrieve value from ThemedResourceCache#mUnthemedEntries", e5);
            longSparseArray = null;
        }
        if (longSparseArray != null) {
            longSparseArray.clear();
        }
    }
}
