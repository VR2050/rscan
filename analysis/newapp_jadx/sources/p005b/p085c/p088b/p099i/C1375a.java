package p005b.p085c.p088b.p099i;

import android.content.Context;
import android.text.TextUtils;
import java.util.Random;
import org.json.JSONObject;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.i.a */
/* loaded from: classes.dex */
public class C1375a {

    /* renamed from: a */
    public static Context f1260a;

    /* renamed from: b */
    public static C1375a f1261b;

    /* renamed from: c */
    public String f1262c;

    /* renamed from: d */
    public String f1263d;

    /* renamed from: e */
    public long f1264e;

    /* renamed from: f */
    public String f1265f;

    /* renamed from: g */
    public String f1266g;

    /* renamed from: h */
    public boolean f1267h = false;

    /* renamed from: a */
    public static synchronized C1375a m420a(Context context) {
        C1375a c1375a;
        synchronized (C1375a.class) {
            if (f1261b == null) {
                f1261b = new C1375a();
            }
            if (f1260a == null) {
                f1261b.m422c(context);
            }
            c1375a = f1261b;
        }
        return c1375a;
    }

    /* renamed from: b */
    public void m421b(String str, String str2) {
        C4195m.m4787T("mspl", "tid_str: save");
        if (TextUtils.isEmpty(str) || TextUtils.isEmpty(str2)) {
            return;
        }
        this.f1262c = str;
        this.f1263d = str2;
        this.f1264e = System.currentTimeMillis();
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("tid", this.f1262c);
            jSONObject.put("client_key", this.f1263d);
            jSONObject.put("timestamp", this.f1264e);
            jSONObject.put("vimei", this.f1265f);
            jSONObject.put("vimsi", this.f1266g);
            C4195m.m4814k("alipay_tid_storage", "tidinfo", jSONObject.toString(), true);
        } catch (Exception e2) {
            C4195m.m4816l(e2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00d3  */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m422c(android.content.Context r13) {
        /*
            r12 = this;
            if (r13 == 0) goto L8
            android.content.Context r13 = r13.getApplicationContext()
            p005b.p085c.p088b.p099i.C1375a.f1260a = r13
        L8:
            boolean r13 = r12.f1267h
            if (r13 == 0) goto Ld
            return
        Ld:
            r13 = 1
            r12.f1267h = r13
            java.lang.String r0 = "tidinfo"
            java.lang.String r1 = "alipay_tid_storage"
            java.lang.String r2 = ""
            long r3 = java.lang.System.currentTimeMillis()
            java.lang.Long r3 = java.lang.Long.valueOf(r3)
            r4 = 0
            java.lang.String r5 = p403d.p404a.p405a.p407b.p408a.C4195m.m4806g(r1, r0, r13)     // Catch: java.lang.Exception -> L60
            boolean r6 = android.text.TextUtils.isEmpty(r5)     // Catch: java.lang.Exception -> L60
            if (r6 != 0) goto L5c
            org.json.JSONObject r6 = new org.json.JSONObject     // Catch: java.lang.Exception -> L60
            r6.<init>(r5)     // Catch: java.lang.Exception -> L60
            java.lang.String r5 = "tid"
            java.lang.String r5 = r6.optString(r5, r2)     // Catch: java.lang.Exception -> L60
            java.lang.String r7 = "client_key"
            java.lang.String r7 = r6.optString(r7, r2)     // Catch: java.lang.Exception -> L5a
            java.lang.String r8 = "timestamp"
            long r9 = java.lang.System.currentTimeMillis()     // Catch: java.lang.Exception -> L57
            long r8 = r6.optLong(r8, r9)     // Catch: java.lang.Exception -> L57
            java.lang.Long r3 = java.lang.Long.valueOf(r8)     // Catch: java.lang.Exception -> L57
            java.lang.String r8 = "vimei"
            java.lang.String r8 = r6.optString(r8, r2)     // Catch: java.lang.Exception -> L57
            java.lang.String r9 = "vimsi"
            java.lang.String r4 = r6.optString(r9, r2)     // Catch: java.lang.Exception -> L55
            goto L68
        L55:
            r6 = move-exception
            goto L65
        L57:
            r6 = move-exception
            r8 = r4
            goto L65
        L5a:
            r6 = move-exception
            goto L63
        L5c:
            r5 = r4
            r7 = r5
            r8 = r7
            goto L6b
        L60:
            r5 = move-exception
            r6 = r5
            r5 = r4
        L63:
            r7 = r4
            r8 = r7
        L65:
            p403d.p404a.p405a.p407b.p408a.C4195m.m4816l(r6)
        L68:
            r11 = r5
            r5 = r4
            r4 = r11
        L6b:
            java.lang.String r6 = "mspl"
            java.lang.String r9 = "tid_str: load"
            p403d.p404a.p405a.p407b.p408a.C4195m.m4787T(r6, r9)
            boolean r6 = android.text.TextUtils.isEmpty(r4)
            r9 = 0
            if (r6 != 0) goto L8d
            boolean r6 = android.text.TextUtils.isEmpty(r7)
            if (r6 != 0) goto L8d
            boolean r6 = android.text.TextUtils.isEmpty(r8)
            if (r6 != 0) goto L8d
            boolean r6 = android.text.TextUtils.isEmpty(r5)
            if (r6 == 0) goto L8c
            goto L8d
        L8c:
            r13 = 0
        L8d:
            if (r13 == 0) goto Ld3
            r12.f1262c = r2
            long r2 = java.lang.System.currentTimeMillis()
            java.lang.String r13 = java.lang.Long.toHexString(r2)
            int r2 = r13.length()
            r3 = 10
            if (r2 <= r3) goto Laa
            int r2 = r13.length()
            int r2 = r2 - r3
            java.lang.String r13 = r13.substring(r2)
        Laa:
            r12.f1263d = r13
            long r2 = java.lang.System.currentTimeMillis()
            r12.f1264e = r2
            java.lang.String r13 = r12.m423d()
            r12.f1265f = r13
            java.lang.String r13 = r12.m423d()
            r12.f1266g = r13
            android.content.Context r13 = p005b.p085c.p088b.p099i.C1375a.f1260a
            if (r13 != 0) goto Lc3
            goto Le1
        Lc3:
            android.content.SharedPreferences r13 = r13.getSharedPreferences(r1, r9)
            android.content.SharedPreferences$Editor r13 = r13.edit()
            android.content.SharedPreferences$Editor r13 = r13.remove(r0)
            r13.apply()
            goto Le1
        Ld3:
            r12.f1262c = r4
            r12.f1263d = r7
            long r0 = r3.longValue()
            r12.f1264e = r0
            r12.f1265f = r8
            r12.f1266g = r5
        Le1:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p085c.p088b.p099i.C1375a.m422c(android.content.Context):void");
    }

    /* renamed from: d */
    public final String m423d() {
        String hexString = Long.toHexString(System.currentTimeMillis());
        Random random = new Random();
        StringBuilder m586H = C1499a.m586H(hexString);
        m586H.append(random.nextInt(9000) + 1000);
        return m586H.toString();
    }
}
