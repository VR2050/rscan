package p005b.p085c.p088b.p098h;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.os.Process;
import android.os.SystemClock;
import android.text.TextUtils;
import androidx.core.app.NotificationCompat;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Locale;
import java.util.UUID;
import org.json.JSONObject;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p089a.p090h.C1354d;
import p005b.p085c.p088b.p092c.C1356a;
import p005b.p085c.p088b.p100j.C1383h;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.h.a */
/* loaded from: classes.dex */
public class C1373a {

    /* renamed from: a */
    public String f1247a;

    /* renamed from: b */
    public String f1248b;

    /* renamed from: c */
    public Context f1249c;

    /* renamed from: d */
    public final String f1250d;

    /* renamed from: e */
    public final long f1251e;

    /* renamed from: f */
    public final int f1252f;

    /* renamed from: g */
    public final String f1253g;

    /* renamed from: h */
    public final ActivityInfo f1254h;

    /* renamed from: i */
    public final C1354d f1255i;

    /* renamed from: b.c.b.h.a$a */
    public static final class a {

        /* renamed from: a */
        public static final HashMap<UUID, C1373a> f1256a = new HashMap<>();

        /* renamed from: b */
        public static final HashMap<String, C1373a> f1257b = new HashMap<>();

        /* renamed from: a */
        public static C1373a m415a(Intent intent) {
            if (intent == null) {
                return null;
            }
            Serializable serializableExtra = intent.getSerializableExtra("i_uuid_b_c");
            if (serializableExtra instanceof UUID) {
                return f1256a.remove((UUID) serializableExtra);
            }
            return null;
        }

        /* renamed from: b */
        public static void m416b(C1373a c1373a, Intent intent) {
            if (c1373a != null) {
                UUID randomUUID = UUID.randomUUID();
                f1256a.put(randomUUID, c1373a);
                intent.putExtra("i_uuid_b_c", randomUUID);
            }
        }
    }

    public C1373a(Context context, String str, String str2) {
        String str3;
        int i2;
        ActivityInfo activityInfo;
        int i3;
        this.f1247a = "";
        this.f1248b = "";
        String str4 = null;
        this.f1249c = null;
        boolean isEmpty = TextUtils.isEmpty(str2);
        this.f1255i = new C1354d(context, isEmpty);
        String str5 = this.f1248b;
        try {
            Locale locale = Locale.getDefault();
            Object[] objArr = new Object[4];
            objArr[0] = str == null ? "" : str;
            objArr[1] = str5 == null ? "" : str5;
            objArr[2] = Long.valueOf(System.currentTimeMillis());
            objArr[3] = UUID.randomUUID().toString();
            str3 = String.format("EP%s%s_%s", "1", C1383h.m452p(String.format(locale, "%s%s%d%s", objArr)), Long.valueOf(System.currentTimeMillis()));
        } catch (Throwable unused) {
            str3 = "-";
        }
        this.f1250d = str3;
        this.f1251e = SystemClock.elapsedRealtime();
        try {
            i2 = Process.myUid();
        } catch (Throwable th) {
            C4195m.m4816l(th);
            i2 = -200;
        }
        this.f1252f = i2;
        try {
            if (context instanceof Activity) {
                Activity activity = (Activity) context;
                ActivityInfo[] activityInfoArr = context.getPackageManager().getPackageInfo(context.getPackageName(), 1).activities;
                int length = activityInfoArr.length;
                for (int i4 = 0; i4 < length; i4++) {
                    activityInfo = activityInfoArr[i4];
                    if (TextUtils.equals(activityInfo.name, activity.getClass().getName())) {
                        break;
                    }
                }
            }
        } catch (Throwable th2) {
            C4195m.m4816l(th2);
        }
        activityInfo = null;
        this.f1254h = activityInfo;
        this.f1253g = str2;
        if (!isEmpty) {
            StringBuilder m590L = C1499a.m590L(str2, "|");
            m590L.append(this.f1250d);
            C1353c.m367h(this, "biz", "eptyp", m590L.toString());
            C1353c.m367h(this, "biz", "actInfo", activityInfo != null ? activityInfo.name + "|" + activityInfo.launchMode : "null");
            try {
                str4 = (String) Class.forName("android.os.SystemProperties").getMethod("get", String.class).invoke(null, "ro.build.fingerprint");
            } catch (Exception e2) {
                C1353c.m362c(this, "biz", "rflex", e2.getClass().getSimpleName());
            }
            C1353c.m367h(this, "biz", NotificationCompat.CATEGORY_SYSTEM, str4);
        }
        try {
            this.f1249c = context.getApplicationContext();
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            this.f1247a = packageInfo.versionName;
            this.f1248b = packageInfo.packageName;
        } catch (Exception e3) {
            C4195m.m4816l(e3);
        }
        if (!isEmpty) {
            StringBuilder m586H = C1499a.m586H("u");
            try {
                i3 = Process.myUid();
            } catch (Throwable th3) {
                C4195m.m4816l(th3);
                i3 = -200;
            }
            m586H.append(i3);
            C1353c.m361b(this, "biz", m586H.toString());
            C1353c.m367h(this, "biz", "PgApiInvoke", "" + SystemClock.elapsedRealtime());
            C1353c.m360a(context, this, str, this.f1250d);
        }
        if (isEmpty || !C1356a.m376d().f1210o) {
            return;
        }
        C1356a.m376d().m378b(this, this.f1249c);
    }

    /* renamed from: d */
    public static HashMap<String, String> m409d(C1373a c1373a) {
        HashMap<String, String> hashMap = new HashMap<>();
        if (c1373a != null) {
            hashMap.put("sdk_ver", "15.7.7");
            hashMap.put("app_name", c1373a.f1248b);
            hashMap.put("token", c1373a.f1250d);
            hashMap.put("call_type", c1373a.f1253g);
            hashMap.put("ts_api_invoke", String.valueOf(c1373a.f1251e));
        }
        return hashMap;
    }

    /* renamed from: a */
    public String m410a(String str) {
        if (TextUtils.isEmpty(str) || str.startsWith("new_external_info==")) {
            return str;
        }
        if (!str.contains("\"&")) {
            try {
                String m412c = m412c(str, "&", "bizcontext=");
                if (TextUtils.isEmpty(m412c)) {
                    str = str + "&" + m414f("bizcontext=", "");
                } else {
                    int indexOf = str.indexOf(m412c);
                    str = str.substring(0, indexOf) + m413e(m412c, "bizcontext=", "") + str.substring(indexOf + m412c.length());
                }
            } catch (Throwable unused) {
            }
            return str;
        }
        try {
            String m412c2 = m412c(str, "\"&", "bizcontext=\"");
            if (TextUtils.isEmpty(m412c2)) {
                return str + "&" + m414f("bizcontext=\"", "\"");
            }
            if (!m412c2.endsWith("\"")) {
                m412c2 = m412c2 + "\"";
            }
            int indexOf2 = str.indexOf(m412c2);
            return str.substring(0, indexOf2) + m413e(m412c2, "bizcontext=\"", "\"") + str.substring(indexOf2 + m412c2.length());
        } catch (Throwable unused2) {
            return str;
        }
    }

    /* renamed from: b */
    public String m411b(String str, String str2) {
        String str3;
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("appkey", "2014052600006128");
            jSONObject.put("ty", "and_lite");
            jSONObject.put("sv", "h.a.3.7.7");
            if (!this.f1248b.contains("setting") || !C1383h.m446j(this.f1249c)) {
                jSONObject.put("an", this.f1248b);
            }
            jSONObject.put("av", this.f1247a);
            jSONObject.put("sdk_start_time", System.currentTimeMillis());
            JSONObject jSONObject2 = new JSONObject();
            try {
                jSONObject2.put("ap_link_token", this.f1250d);
            } catch (Throwable unused) {
            }
            jSONObject.put("extInfo", jSONObject2);
            if (this.f1254h != null) {
                str3 = this.f1254h.name + "|" + this.f1254h.launchMode;
            } else {
                str3 = "null";
            }
            jSONObject.put("act_info", str3);
            if (!TextUtils.isEmpty(str)) {
                jSONObject.put(str, str2);
            }
            return jSONObject.toString();
        } catch (Throwable th) {
            C4195m.m4816l(th);
            return "";
        }
    }

    /* renamed from: c */
    public final String m412c(String str, String str2, String str3) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        String[] split = str.split(str2);
        for (int i2 = 0; i2 < split.length; i2++) {
            if (!TextUtils.isEmpty(split[i2]) && split[i2].startsWith(str3)) {
                return split[i2];
            }
        }
        return null;
    }

    /* renamed from: e */
    public final String m413e(String str, String str2, String str3) {
        JSONObject jSONObject;
        String substring = str.substring(str2.length());
        boolean z = false;
        String substring2 = substring.substring(0, substring.length() - str3.length());
        if (substring2.length() >= 2 && substring2.startsWith("\"") && substring2.endsWith("\"")) {
            jSONObject = new JSONObject(substring2.substring(1, substring2.length() - 1));
            z = true;
        } else {
            jSONObject = new JSONObject(substring2);
        }
        if (!jSONObject.has("appkey")) {
            jSONObject.put("appkey", "2014052600006128");
        }
        if (!jSONObject.has("ty")) {
            jSONObject.put("ty", "and_lite");
        }
        if (!jSONObject.has("sv")) {
            jSONObject.put("sv", "h.a.3.7.7");
        }
        if (!jSONObject.has("an") && (!this.f1248b.contains("setting") || !C1383h.m446j(this.f1249c))) {
            jSONObject.put("an", this.f1248b);
        }
        if (!jSONObject.has("av")) {
            jSONObject.put("av", this.f1247a);
        }
        if (!jSONObject.has("sdk_start_time")) {
            jSONObject.put("sdk_start_time", System.currentTimeMillis());
        }
        if (!jSONObject.has("extInfo")) {
            JSONObject jSONObject2 = new JSONObject();
            try {
                jSONObject2.put("ap_link_token", this.f1250d);
            } catch (Throwable unused) {
            }
            jSONObject.put("extInfo", jSONObject2);
        }
        String jSONObject3 = jSONObject.toString();
        if (z) {
            jSONObject3 = C1499a.m639y("\"", jSONObject3, "\"");
        }
        return C1499a.m639y(str2, jSONObject3, str3);
    }

    /* renamed from: f */
    public final String m414f(String str, String str2) {
        return C1499a.m639y(str, m411b("", ""), str2);
    }
}
