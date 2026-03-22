package p005b.p293n.p294a;

import android.app.Activity;
import android.app.AppOpsManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.view.Display;
import android.view.WindowManager;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.n.a.e0 */
/* loaded from: classes2.dex */
public final class C2645e0 {

    /* renamed from: a */
    public static final Handler f7223a = new Handler(Looper.getMainLooper());

    /* renamed from: a */
    public static boolean m3115a(@NonNull Context context, @Nullable Intent intent) {
        if (intent == null) {
            return false;
        }
        PackageManager packageManager = context.getPackageManager();
        return C2354n.m2384D0() ? !packageManager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(IjkMediaMeta.AV_CH_TOP_BACK_CENTER)).isEmpty() : !packageManager.queryIntentActivities(intent, 65536).isEmpty();
    }

    @NonNull
    /* renamed from: b */
    public static <T> ArrayList<T> m3116b(@Nullable T... tArr) {
        ArrayList<T> arrayList = new ArrayList<>(tArr.length);
        if (tArr.length != 0) {
            for (T t : tArr) {
                arrayList.add(t);
            }
        }
        return arrayList;
    }

    @RequiresApi(19)
    /* renamed from: c */
    public static boolean m3117c(Context context, String str) {
        AppOpsManager appOpsManager = (AppOpsManager) context.getSystemService("appops");
        return (C2354n.m2375A0() ? appOpsManager.unsafeCheckOpNoThrow(str, context.getApplicationInfo().uid, context.getPackageName()) : appOpsManager.checkOpNoThrow(str, context.getApplicationInfo().uid, context.getPackageName())) == 0;
    }

    @RequiresApi(19)
    /* renamed from: d */
    public static boolean m3118d(Context context, String str, int i2) {
        Class<?> cls;
        Class<?> cls2;
        AppOpsManager appOpsManager = (AppOpsManager) context.getSystemService("appops");
        ApplicationInfo applicationInfo = context.getApplicationInfo();
        String packageName = context.getApplicationContext().getPackageName();
        int i3 = applicationInfo.uid;
        try {
            cls = Class.forName(AppOpsManager.class.getName());
            try {
                i2 = ((Integer) cls.getDeclaredField(str).get(Integer.class)).intValue();
            } catch (NoSuchFieldException e2) {
                e2.printStackTrace();
            }
            cls2 = Integer.TYPE;
        } catch (ClassNotFoundException | IllegalAccessException | NoSuchMethodException | RuntimeException | InvocationTargetException unused) {
        }
        return ((Integer) cls.getMethod("checkOpNoThrow", cls2, cls2, String.class).invoke(appOpsManager, Integer.valueOf(i2), Integer.valueOf(i3), packageName)).intValue() == 0;
    }

    /* renamed from: e */
    public static boolean m3119e(@NonNull Collection<String> collection, @NonNull String str) {
        if (collection.isEmpty()) {
            return false;
        }
        Iterator<String> it = collection.iterator();
        while (it.hasNext()) {
            if (m3121g(it.next(), str)) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: f */
    public static boolean m3120f(@NonNull String[] strArr, @NonNull String str) {
        return m3119e(Arrays.asList(strArr), str);
    }

    /* renamed from: g */
    public static boolean m3121g(@NonNull String str, @NonNull String str2) {
        int length = str.length();
        if (length != str2.length()) {
            return false;
        }
        for (int i2 = length - 1; i2 >= 0; i2--) {
            if (str.charAt(i2) != str2.charAt(i2)) {
                return false;
            }
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0092 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0093 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @androidx.annotation.Nullable
    /* renamed from: h */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p005b.p293n.p294a.C2648g m3122h(android.content.Context r10) {
        /*
            android.content.pm.ApplicationInfo r0 = r10.getApplicationInfo()
            java.lang.String r0 = r0.sourceDir
            java.lang.Class<java.lang.String> r1 = java.lang.String.class
            android.content.res.AssetManager r2 = r10.getAssets()
            r3 = 0
            android.content.pm.ApplicationInfo r4 = r10.getApplicationInfo()     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            int r4 = r4.targetSdkVersion     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            r5 = 28
            r6 = 1
            if (r4 < r5) goto L62
            int r4 = android.os.Build.VERSION.SDK_INT     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            if (r4 < r5) goto L62
            r5 = 30
            if (r4 >= r5) goto L62
            java.lang.Class<java.lang.Class> r4 = java.lang.Class.class
            java.lang.String r5 = "getDeclaredMethod"
            r7 = 2
            java.lang.Class[] r8 = new java.lang.Class[r7]     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            r8[r3] = r1     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Class<java.lang.Class[]> r9 = java.lang.Class[].class
            r8[r6] = r9     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.reflect.Method r4 = r4.getDeclaredMethod(r5, r8)     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            r4.setAccessible(r6)     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Class<android.content.res.AssetManager> r5 = android.content.res.AssetManager.class
            java.lang.Object[] r7 = new java.lang.Object[r7]     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.String r8 = "findCookieForPath"
            r7[r3] = r8     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Class[] r8 = new java.lang.Class[r6]     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            r8[r3] = r1     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            r7[r6] = r8     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Object r4 = r4.invoke(r5, r7)     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.reflect.Method r4 = (java.lang.reflect.Method) r4     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            if (r4 == 0) goto L62
            r4.setAccessible(r6)     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            android.content.res.AssetManager r5 = r10.getAssets()     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Object[] r7 = new java.lang.Object[r6]     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            r7[r3] = r0     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Object r4 = r4.invoke(r5, r7)     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Integer r4 = (java.lang.Integer) r4     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            if (r4 == 0) goto L62
            int r3 = r4.intValue()     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            goto L8f
        L62:
            java.lang.Class r4 = r2.getClass()     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.String r5 = "addAssetPath"
            java.lang.Class[] r7 = new java.lang.Class[r6]     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            r7[r3] = r1     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.reflect.Method r1 = r4.getDeclaredMethod(r5, r7)     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Object[] r4 = new java.lang.Object[r6]     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            r4[r3] = r0     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Object r0 = r1.invoke(r2, r4)     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            java.lang.Integer r0 = (java.lang.Integer) r0     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            if (r0 == 0) goto L8f
            int r3 = r0.intValue()     // Catch: java.lang.reflect.InvocationTargetException -> L81 java.lang.IllegalAccessException -> L86 java.lang.NoSuchMethodException -> L8b
            goto L8f
        L81:
            r0 = move-exception
            r0.printStackTrace()
            goto L8f
        L86:
            r0 = move-exception
            r0.printStackTrace()
            goto L8f
        L8b:
            r0 = move-exception
            r0.printStackTrace()
        L8f:
            r0 = 0
            if (r3 != 0) goto L93
            return r0
        L93:
            b.n.a.g r1 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2490k1(r10, r3)     // Catch: org.xmlpull.v1.XmlPullParserException -> La9 java.io.IOException -> Lab
            java.lang.String r10 = r10.getPackageName()     // Catch: org.xmlpull.v1.XmlPullParserException -> La4 java.io.IOException -> La6
            java.lang.String r2 = r1.f7238a     // Catch: org.xmlpull.v1.XmlPullParserException -> La4 java.io.IOException -> La6
            boolean r10 = android.text.TextUtils.equals(r10, r2)     // Catch: org.xmlpull.v1.XmlPullParserException -> La4 java.io.IOException -> La6
            if (r10 != 0) goto Lb0
            return r0
        La4:
            r10 = move-exception
            goto La7
        La6:
            r10 = move-exception
        La7:
            r0 = r1
            goto Lac
        La9:
            r10 = move-exception
            goto Lac
        Lab:
            r10 = move-exception
        Lac:
            r10.printStackTrace()
            r1 = r0
        Lb0:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p293n.p294a.C2645e0.m3122h(android.content.Context):b.n.a.g");
    }

    /* renamed from: i */
    public static Uri m3123i(@NonNull Context context) {
        StringBuilder m586H = C1499a.m586H("package:");
        m586H.append(context.getPackageName());
        return Uri.parse(m586H.toString());
    }

    /* renamed from: j */
    public static String m3124j(String str) {
        BufferedReader bufferedReader = null;
        try {
            BufferedReader bufferedReader2 = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec("getprop " + str).getInputStream()), 1024);
            try {
                String readLine = bufferedReader2.readLine();
                if (readLine != null) {
                    try {
                        bufferedReader2.close();
                    } catch (IOException unused) {
                    }
                    return readLine;
                }
                try {
                    bufferedReader2.close();
                } catch (IOException unused2) {
                }
                return null;
            } catch (Throwable th) {
                th = th;
                bufferedReader = bufferedReader2;
                if (bufferedReader != null) {
                    try {
                        bufferedReader.close();
                    } catch (IOException unused3) {
                    }
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    @NonNull
    /* renamed from: k */
    public static String m3125k(String str) {
        String property;
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            String str2 = (String) cls.getMethod("get", String.class, String.class).invoke(cls, str, "");
            if (str2 != null) {
                if (!str2.isEmpty()) {
                    return str2;
                }
            }
        } catch (Exception unused) {
        }
        try {
            String m3124j = m3124j(str);
            if (m3124j != null) {
                if (!m3124j.isEmpty()) {
                    return m3124j;
                }
            }
        } catch (IOException unused2) {
        }
        FileInputStream fileInputStream = null;
        try {
            try {
                Properties properties = new Properties();
                FileInputStream fileInputStream2 = new FileInputStream(new File(Environment.getRootDirectory(), "build.prop"));
                try {
                    properties.load(fileInputStream2);
                    property = properties.getProperty(str, "");
                    try {
                        fileInputStream2.close();
                    } catch (IOException unused3) {
                    }
                } catch (Throwable th) {
                    th = th;
                    fileInputStream = fileInputStream2;
                    if (fileInputStream != null) {
                        try {
                            fileInputStream.close();
                        } catch (IOException unused4) {
                        }
                    }
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (IOException unused5) {
        }
        return (property == null || property.isEmpty()) ? "" : property;
    }

    /* renamed from: l */
    public static boolean m3126l(@NonNull Activity activity) {
        Display defaultDisplay;
        if (C2354n.m2378B0()) {
            defaultDisplay = activity.getDisplay();
        } else {
            WindowManager windowManager = activity.getWindowManager();
            defaultDisplay = windowManager != null ? windowManager.getDefaultDisplay() : null;
        }
        if (defaultDisplay == null) {
            return false;
        }
        int rotation = defaultDisplay.getRotation();
        return rotation == 2 || rotation == 3;
    }

    @RequiresApi(api = 23)
    /* renamed from: m */
    public static boolean m3127m(@NonNull Activity activity, @NonNull String str) {
        if (Build.VERSION.SDK_INT == 31) {
            try {
                return ((Boolean) PackageManager.class.getMethod("shouldShowRequestPermissionRationale", String.class).invoke(activity.getApplication().getPackageManager(), str)).booleanValue();
            } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException e2) {
                e2.printStackTrace();
            }
        }
        return activity.shouldShowRequestPermissionRationale(str);
    }
}
