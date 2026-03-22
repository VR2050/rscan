package p005b.p293n.p294a;

import android.annotation.SuppressLint;
import android.os.Build;
import android.text.TextUtils;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.n.a.f0 */
/* loaded from: classes2.dex */
public final class C2647f0 {

    /* renamed from: a */
    public static final String[] f7225a = {"huawei"};

    /* renamed from: b */
    public static final String[] f7226b = {"vivo"};

    /* renamed from: c */
    public static final String[] f7227c = {"xiaomi"};

    /* renamed from: d */
    public static final String[] f7228d = {"oppo"};

    /* renamed from: e */
    public static final String[] f7229e = {"leeco", "letv"};

    /* renamed from: f */
    public static final String[] f7230f = {"360", "qiku"};

    /* renamed from: g */
    public static final String[] f7231g = {"zte"};

    /* renamed from: h */
    public static final String[] f7232h = {"oneplus"};

    /* renamed from: i */
    public static final String[] f7233i = {"nubia"};

    /* renamed from: j */
    public static final String[] f7234j = {"samsung"};

    /* renamed from: k */
    public static final String[] f7235k = {"honor"};

    /* renamed from: l */
    public static final String[] f7236l = {"ro.build.version.opporom", "ro.build.version.oplusrom.display"};

    /* renamed from: m */
    public static final String[] f7237m = {"msc.config.magic.version", "ro.build.version.magic"};

    /* renamed from: a */
    public static String m3128a() {
        return Build.BRAND.toLowerCase();
    }

    /* renamed from: b */
    public static String m3129b() {
        return Build.MANUFACTURER.toLowerCase();
    }

    /* renamed from: c */
    public static boolean m3130c() {
        for (String str : f7236l) {
            if (!TextUtils.isEmpty(C2645e0.m3125k(str))) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: d */
    public static boolean m3131d() {
        if (!C2354n.m2375A0()) {
            return false;
        }
        try {
            Class<?> cls = Class.forName("com.huawei.system.BuildEx");
            return "Harmony".equalsIgnoreCase(String.valueOf(cls.getMethod("getOsBrand", new Class[0]).invoke(cls, new Object[0])));
        } catch (Throwable th) {
            th.printStackTrace();
            return false;
        }
    }

    /* renamed from: e */
    public static boolean m3132e() {
        return !TextUtils.isEmpty(C2645e0.m3125k("ro.miui.ui.version.name"));
    }

    @SuppressLint({"PrivateApi"})
    /* renamed from: f */
    public static boolean m3133f() {
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            String valueOf = String.valueOf(cls.getMethod("get", String.class, String.class).invoke(cls, "ro.miui.cts", ""));
            Method method = cls.getMethod("getBoolean", String.class, Boolean.TYPE);
            Object[] objArr = new Object[2];
            objArr[0] = "persist.sys.miui_optimization";
            objArr[1] = Boolean.valueOf("1".equals(valueOf) ? false : true);
            return Boolean.parseBoolean(String.valueOf(method.invoke(cls, objArr)));
        } catch (ClassNotFoundException e2) {
            e2.printStackTrace();
            return true;
        } catch (IllegalAccessException e3) {
            e3.printStackTrace();
            return true;
        } catch (NoSuchMethodException e4) {
            e4.printStackTrace();
            return true;
        } catch (InvocationTargetException e5) {
            e5.printStackTrace();
            return true;
        }
    }

    /* renamed from: g */
    public static boolean m3134g(String str, String str2, String... strArr) {
        for (String str3 : strArr) {
            if (str.contains(str3) || str2.contains(str3)) {
                return true;
            }
        }
        return false;
    }
}
