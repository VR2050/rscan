package com.alipay.apmobilesecuritysdk.p388a;

import android.content.Context;
import android.os.Environment;
import com.alipay.apmobilesecuritysdk.otherid.UmidSdkWrapper;
import com.alipay.apmobilesecuritysdk.p389b.C3168a;
import com.alipay.apmobilesecuritysdk.p390c.C3169a;
import com.alipay.apmobilesecuritysdk.p391d.C3176e;
import com.alipay.apmobilesecuritysdk.p392e.C3177a;
import com.alipay.apmobilesecuritysdk.p392e.C3178b;
import com.alipay.apmobilesecuritysdk.p392e.C3179c;
import com.alipay.apmobilesecuritysdk.p392e.C3180d;
import com.alipay.apmobilesecuritysdk.p392e.C3183g;
import com.alipay.apmobilesecuritysdk.p392e.C3184h;
import com.alipay.apmobilesecuritysdk.p392e.C3185i;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import p005b.p085c.p102c.p103a.p104a.p110e.p111d.C1405a;
import p005b.p085c.p102c.p103a.p104a.p110e.p111d.C1406b;
import p005b.p085c.p102c.p103a.p104a.p110e.p112e.C1408b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: com.alipay.apmobilesecuritysdk.a.a */
/* loaded from: classes.dex */
public final class C3167a {

    /* renamed from: a */
    private Context f8611a;

    /* renamed from: b */
    private C3168a f8612b = C3168a.m3734a();

    /* renamed from: c */
    private int f8613c = 4;

    public C3167a(Context context) {
        this.f8611a = context;
    }

    /* renamed from: a */
    public static String m3727a(Context context) {
        String m3731b = m3731b(context);
        return C4195m.m4822o(m3731b) ? C3184h.m3796f(context) : m3731b;
    }

    /* renamed from: a */
    public static String m3728a(Context context, String str) {
        try {
            m3732b();
            String m3800a = C3185i.m3800a(str);
            if (!C4195m.m4822o(m3800a)) {
                return m3800a;
            }
            String m3779a = C3183g.m3779a(context, str);
            C3185i.m3804a(str, m3779a);
            return !C4195m.m4822o(m3779a) ? m3779a : "";
        } catch (Throwable unused) {
            return "";
        }
    }

    /* renamed from: a */
    private static boolean m3729a() {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String[] strArr = {"2017-01-27 2017-01-28", "2017-11-10 2017-11-11", "2017-12-11 2017-12-12"};
        int random = ((int) (Math.random() * 24.0d * 60.0d * 60.0d)) * 1;
        for (int i2 = 0; i2 < 3; i2++) {
            try {
                String[] split = strArr[i2].split(" ");
                if (split != null && split.length == 2) {
                    Date date = new Date();
                    Date parse = simpleDateFormat.parse(split[0] + " 00:00:00");
                    Date parse2 = simpleDateFormat.parse(split[1] + " 23:59:59");
                    Calendar calendar = Calendar.getInstance();
                    calendar.setTime(parse2);
                    calendar.add(13, random);
                    Date time = calendar.getTime();
                    if (date.after(parse) && date.before(time)) {
                        return true;
                    }
                }
            } catch (Exception unused) {
            }
        }
        return false;
    }

    /* renamed from: b */
    private C1405a m3730b(Map<String, String> map) {
        C3178b m3758b;
        C3178b m3760c;
        try {
            Context context = this.f8611a;
            C1406b c1406b = new C1406b();
            String m4808h = C4195m.m4808h(map, "appName", "");
            String m4808h2 = C4195m.m4808h(map, "sessionId", "");
            String m4808h3 = C4195m.m4808h(map, "rpcVersion", "");
            String m3728a = m3728a(context, m4808h);
            String securityToken = UmidSdkWrapper.getSecurityToken(context);
            String m3792d = C3184h.m3792d(context);
            if (C4195m.m4840x(m4808h2)) {
                c1406b.f1355c = m4808h2;
            } else {
                c1406b.f1355c = m3728a;
            }
            c1406b.f1356d = securityToken;
            c1406b.f1357e = m3792d;
            c1406b.f1353a = "android";
            C3179c m3767c = C3180d.m3767c(context);
            String str = m3767c != null ? m3767c.f8621a : "";
            if (C4195m.m4822o(str) && (m3760c = C3177a.m3760c(context)) != null) {
                str = m3760c.f8618a;
            }
            C3179c m3765b = C3180d.m3765b();
            String str2 = m3765b != null ? m3765b.f8621a : "";
            if (C4195m.m4822o(str2) && (m3758b = C3177a.m3758b()) != null) {
                str2 = m3758b.f8618a;
            }
            c1406b.f1359g = m4808h3;
            if (C4195m.m4822o(str)) {
                c1406b.f1354b = str2;
            } else {
                c1406b.f1354b = str;
            }
            c1406b.f1358f = C3176e.m3750a(context, map);
            return ((C1408b) C4195m.m4838w(this.f8611a, this.f8612b.m3737c())).m482a(c1406b);
        } catch (Throwable th) {
            th.printStackTrace();
            C3169a.m3740a(th);
            return null;
        }
    }

    /* renamed from: b */
    private static String m3731b(Context context) {
        try {
            String m3806b = C3185i.m3806b();
            if (!C4195m.m4822o(m3806b)) {
                return m3806b;
            }
            C3179c m3766b = C3180d.m3766b(context);
            if (m3766b != null) {
                C3185i.m3803a(m3766b);
                String str = m3766b.f8621a;
                if (C4195m.m4840x(str)) {
                    return str;
                }
            }
            C3178b m3759b = C3177a.m3759b(context);
            if (m3759b == null) {
                return "";
            }
            C3185i.m3802a(m3759b);
            String str2 = m3759b.f8618a;
            return C4195m.m4840x(str2) ? str2 : "";
        } catch (Throwable unused) {
            return "";
        }
    }

    /* renamed from: b */
    private static void m3732b() {
        try {
            String[] strArr = {"device_feature_file_name", "wallet_times", "wxcasxx_v3", "wxcasxx_v4", "wxxzyy_v1"};
            for (int i2 = 0; i2 < 5; i2++) {
                String str = strArr[i2];
                File file = new File(Environment.getExternalStorageDirectory(), ".SystemConfig/" + str);
                if (file.exists() && file.canWrite()) {
                    file.delete();
                }
            }
        } catch (Throwable unused) {
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0217 A[Catch: Exception -> 0x025e, TryCatch #0 {Exception -> 0x025e, blocks: (B:3:0x0006, B:5:0x0037, B:8:0x0040, B:12:0x00be, B:15:0x01fc, B:17:0x0217, B:19:0x021d, B:21:0x0223, B:25:0x022c, B:27:0x0232, B:32:0x00d0, B:34:0x00ea, B:36:0x00ee, B:40:0x00f9, B:46:0x010a, B:47:0x011a, B:48:0x0121, B:53:0x0133, B:56:0x0148, B:58:0x0189, B:60:0x0193, B:61:0x019b, B:63:0x01a8, B:65:0x01b2, B:66:0x01ba, B:67:0x01b6, B:68:0x0197, B:69:0x0055, B:71:0x0063, B:74:0x006e, B:76:0x0074, B:79:0x007f, B:82:0x0088, B:85:0x0095, B:89:0x00a2, B:91:0x00b0), top: B:2:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x021d A[Catch: Exception -> 0x025e, TryCatch #0 {Exception -> 0x025e, blocks: (B:3:0x0006, B:5:0x0037, B:8:0x0040, B:12:0x00be, B:15:0x01fc, B:17:0x0217, B:19:0x021d, B:21:0x0223, B:25:0x022c, B:27:0x0232, B:32:0x00d0, B:34:0x00ea, B:36:0x00ee, B:40:0x00f9, B:46:0x010a, B:47:0x011a, B:48:0x0121, B:53:0x0133, B:56:0x0148, B:58:0x0189, B:60:0x0193, B:61:0x019b, B:63:0x01a8, B:65:0x01b2, B:66:0x01ba, B:67:0x01b6, B:68:0x0197, B:69:0x0055, B:71:0x0063, B:74:0x006e, B:76:0x0074, B:79:0x007f, B:82:0x0088, B:85:0x0095, B:89:0x00a2, B:91:0x00b0), top: B:2:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:25:0x022c A[Catch: Exception -> 0x025e, TryCatch #0 {Exception -> 0x025e, blocks: (B:3:0x0006, B:5:0x0037, B:8:0x0040, B:12:0x00be, B:15:0x01fc, B:17:0x0217, B:19:0x021d, B:21:0x0223, B:25:0x022c, B:27:0x0232, B:32:0x00d0, B:34:0x00ea, B:36:0x00ee, B:40:0x00f9, B:46:0x010a, B:47:0x011a, B:48:0x0121, B:53:0x0133, B:56:0x0148, B:58:0x0189, B:60:0x0193, B:61:0x019b, B:63:0x01a8, B:65:0x01b2, B:66:0x01ba, B:67:0x01b6, B:68:0x0197, B:69:0x0055, B:71:0x0063, B:74:0x006e, B:76:0x0074, B:79:0x007f, B:82:0x0088, B:85:0x0095, B:89:0x00a2, B:91:0x00b0), top: B:2:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00d0 A[Catch: Exception -> 0x025e, TryCatch #0 {Exception -> 0x025e, blocks: (B:3:0x0006, B:5:0x0037, B:8:0x0040, B:12:0x00be, B:15:0x01fc, B:17:0x0217, B:19:0x021d, B:21:0x0223, B:25:0x022c, B:27:0x0232, B:32:0x00d0, B:34:0x00ea, B:36:0x00ee, B:40:0x00f9, B:46:0x010a, B:47:0x011a, B:48:0x0121, B:53:0x0133, B:56:0x0148, B:58:0x0189, B:60:0x0193, B:61:0x019b, B:63:0x01a8, B:65:0x01b2, B:66:0x01ba, B:67:0x01b6, B:68:0x0197, B:69:0x0055, B:71:0x0063, B:74:0x006e, B:76:0x0074, B:79:0x007f, B:82:0x0088, B:85:0x0095, B:89:0x00a2, B:91:0x00b0), top: B:2:0x0006 }] */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int m3733a(java.util.Map<java.lang.String, java.lang.String> r12) {
        /*
            Method dump skipped, instructions count: 613
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alipay.apmobilesecuritysdk.p388a.C3167a.m3733a(java.util.Map):int");
    }
}
