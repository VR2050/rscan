package p005b.p293n.p294a;

import android.app.AppOpsManager;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.provider.Settings;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p293n.p294a.C2648g;

/* renamed from: b.n.a.h */
/* loaded from: classes2.dex */
public final class C2650h {
    /* renamed from: a */
    public static Intent m3138a(@Nullable Intent intent, @Nullable Intent intent2) {
        if (intent == null && intent2 != null) {
            return intent2;
        }
        if (intent2 == null) {
            return intent;
        }
        Intent m3141d = m3141d(intent);
        (m3141d != null ? m3140c(m3141d) : intent).putExtra("sub_intent_key", intent2);
        return intent;
    }

    /* renamed from: b */
    public static void m3139b(@NonNull List<C2648g.c> list, String str, int i2) {
        C2648g.c cVar;
        Iterator<C2648g.c> it = list.iterator();
        while (true) {
            if (!it.hasNext()) {
                cVar = null;
                break;
            } else {
                cVar = it.next();
                if (TextUtils.equals(cVar.f7247b, str)) {
                    break;
                }
            }
        }
        if (cVar == null) {
            throw new IllegalStateException(C1499a.m639y("Please register permissions in the AndroidManifest.xml file <uses-permission android:name=\"", str, "\" />"));
        }
        int i3 = cVar.f7248c;
        if (i3 < i2) {
            StringBuilder sb = new StringBuilder();
            sb.append("The AndroidManifest.xml file <uses-permission android:name=\"");
            sb.append(str);
            sb.append("\" android:maxSdkVersion=\"");
            sb.append(i3);
            sb.append("\" /> does not meet the requirements, ");
            sb.append(i2 != Integer.MAX_VALUE ? C1499a.m626l("the minimum requirement for maxSdkVersion is ", i2) : C1499a.m628n("please delete the android:maxSdkVersion=\"", i3, "\" attribute"));
            throw new IllegalArgumentException(sb.toString());
        }
    }

    /* renamed from: c */
    public static Intent m3140c(@NonNull Intent intent) {
        Intent m3141d = m3141d(intent);
        return m3141d != null ? m3140c(m3141d) : intent;
    }

    /* renamed from: d */
    public static Intent m3141d(@NonNull Intent intent) {
        return C2354n.m2384D0() ? (Intent) intent.getParcelableExtra("sub_intent_key", Intent.class) : (Intent) intent.getParcelableExtra("sub_intent_key");
    }

    @NonNull
    /* renamed from: e */
    public static Intent m3142e(@NonNull Context context) {
        return m3143f(context, null);
    }

    @NonNull
    /* renamed from: f */
    public static Intent m3143f(@NonNull Context context, @Nullable List<String> list) {
        Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
        intent.setData(C2645e0.m3123i(context));
        if (list != null && !list.isEmpty() && C2647f0.m3130c()) {
            Bundle bundle = new Bundle();
            bundle.putStringArrayList("permissionList", list instanceof ArrayList ? (ArrayList) list : new ArrayList<>(list));
            intent.putExtras(bundle);
            intent.putExtra("isGetPermission", true);
        }
        if (C2645e0.m3115a(context, intent)) {
            return intent;
        }
        Intent intent2 = new Intent("android.settings.APPLICATION_SETTINGS");
        if (C2645e0.m3115a(context, intent2)) {
            return intent2;
        }
        Intent intent3 = new Intent("android.settings.MANAGE_APPLICATIONS_SETTINGS");
        return C2645e0.m3115a(context, intent3) ? intent3 : new Intent("android.settings.SETTINGS");
    }

    @Nullable
    /* renamed from: g */
    public static Intent m3144g(Context context) {
        Intent putExtra = new Intent().setAction("miui.intent.action.APP_PERM_EDITOR").putExtra("extra_pkgname", context.getPackageName());
        Intent launchIntentForPackage = context.getPackageManager().getLaunchIntentForPackage("com.miui.securitycenter");
        if (!C2645e0.m3115a(context, launchIntentForPackage)) {
            launchIntentForPackage = null;
        }
        if (!C2645e0.m3115a(context, putExtra)) {
            putExtra = null;
        }
        return C2645e0.m3115a(context, launchIntentForPackage) ? m3138a(putExtra, launchIntentForPackage) : putExtra;
    }

    /* renamed from: h */
    public static Intent m3145h(@NonNull Context context) {
        Intent intent;
        if (C2354n.m2393G0()) {
            intent = new Intent("android.settings.APP_NOTIFICATION_SETTINGS");
            intent.putExtra("android.provider.extra.APP_PACKAGE", context.getPackageName());
        } else {
            intent = new Intent();
            intent.setAction("android.settings.APP_NOTIFICATION_SETTINGS");
            intent.putExtra("app_package", context.getPackageName());
            intent.putExtra("app_uid", context.getApplicationInfo().uid);
        }
        return !C2645e0.m3115a(context, intent) ? m3142e(context) : intent;
    }

    /* renamed from: i */
    public static boolean m3146i(@NonNull Context context) {
        if (C2354n.m2390F0() && m3149l(context)) {
            Handler handler = C2645e0.f7223a;
            return context.checkSelfPermission("com.android.permission.GET_INSTALLED_APPS") == 0;
        }
        if (C2647f0.m3132e() && m3148k() && C2647f0.m3133f()) {
            return C2645e0.m3118d(context, "OP_GET_INSTALLED_APPS", 10022);
        }
        return true;
    }

    /* renamed from: j */
    public static boolean m3147j(@NonNull Context context) {
        return Build.VERSION.SDK_INT >= 24 ? ((NotificationManager) context.getSystemService(NotificationManager.class)).areNotificationsEnabled() : C2645e0.m3118d(context, "OP_POST_NOTIFICATION", 11);
    }

    /* renamed from: k */
    public static boolean m3148k() {
        try {
            Class.forName(AppOpsManager.class.getName()).getDeclaredField("OP_GET_INSTALLED_APPS");
            return true;
        } catch (ClassNotFoundException e2) {
            e2.printStackTrace();
            return false;
        } catch (NoSuchFieldException e3) {
            e3.printStackTrace();
            return false;
        }
    }

    @RequiresApi(23)
    /* renamed from: l */
    public static boolean m3149l(Context context) {
        try {
            PermissionInfo permissionInfo = context.getPackageManager().getPermissionInfo("com.android.permission.GET_INSTALLED_APPS", 0);
            if (permissionInfo != null) {
                return C2354n.m2396H0() ? permissionInfo.getProtection() == 1 : (permissionInfo.protectionLevel & 15) == 1;
            }
        } catch (PackageManager.NameNotFoundException e2) {
            e2.printStackTrace();
        }
        try {
            return Settings.Secure.getInt(context.getContentResolver(), "oem_installed_apps_runtime_permission_enable") == 1;
        } catch (Settings.SettingNotFoundException e3) {
            e3.printStackTrace();
            return false;
        }
    }

    /* renamed from: m */
    public static boolean m3150m(@NonNull InterfaceC2661o interfaceC2661o, @NonNull Intent intent) {
        try {
            interfaceC2661o.mo3157a(intent);
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            Intent m3141d = m3141d(intent);
            if (m3141d == null) {
                return false;
            }
            return m3150m(interfaceC2661o, m3141d);
        }
    }

    /* renamed from: n */
    public static boolean m3151n(@NonNull InterfaceC2661o interfaceC2661o, @NonNull Intent intent, int i2) {
        try {
            interfaceC2661o.mo3158b(intent, i2);
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            Intent m3141d = m3141d(intent);
            if (m3141d == null) {
                return false;
            }
            return m3151n(interfaceC2661o, m3141d, i2);
        }
    }
}
