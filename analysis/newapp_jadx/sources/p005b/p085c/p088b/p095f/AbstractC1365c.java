package p005b.p085c.p088b.p095f;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.text.TextUtils;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.json.JSONException;
import org.json.JSONObject;
import p005b.p085c.p088b.p089a.C1348e;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p092c.C1359d;
import p005b.p085c.p088b.p094e.C1362a;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p085c.p088b.p098h.C1374b;
import p005b.p085c.p088b.p099i.C1375a;
import p005b.p085c.p088b.p100j.C1383h;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.f.c */
/* loaded from: classes.dex */
public abstract class AbstractC1365c {
    /* renamed from: g */
    public static JSONObject m397g(String str, String str2) {
        JSONObject jSONObject = new JSONObject();
        JSONObject jSONObject2 = new JSONObject();
        jSONObject2.put("type", str);
        jSONObject2.put("method", str2);
        jSONObject.put("action", jSONObject2);
        return jSONObject;
    }

    /* renamed from: h */
    public static boolean m398h(C1362a.b bVar) {
        List<String> list;
        Map<String, List<String>> map = bVar.f1233a;
        return Boolean.valueOf((map == null || (list = map.get("msp-gzip")) == null) ? null : TextUtils.join(ChineseToPinyinResource.Field.COMMA, list)).booleanValue();
    }

    /* renamed from: a */
    public C1363a mo399a(C1373a c1373a, Context context, String str) {
        if (context != null) {
            TextUtils.isEmpty("https://mobilegw.alipay.com/mgw.htm");
        }
        return m400b(c1373a, context, str, "https://mobilegw.alipay.com/mgw.htm", true);
    }

    /* JADX WARN: Removed duplicated region for block: B:111:0x01b3 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:118:? A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0148 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0154  */
    /* JADX WARN: Removed duplicated region for block: B:66:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0142 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:87:0x01a2 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:96:0x01a6  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p085c.p088b.p095f.C1363a m400b(p005b.p085c.p088b.p098h.C1373a r17, android.content.Context r18, java.lang.String r19, java.lang.String r20, boolean r21) {
        /*
            Method dump skipped, instructions count: 445
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p085c.p088b.p095f.AbstractC1365c.m400b(b.c.b.h.a, android.content.Context, java.lang.String, java.lang.String, boolean):b.c.b.f.a");
    }

    /* renamed from: c */
    public String mo401c(C1373a c1373a, String str, JSONObject jSONObject) {
        C1374b m417a = C1374b.m417a();
        C1375a m420a = C1375a.m420a(m417a.f1259b);
        JSONObject jSONObject2 = new JSONObject();
        JSONObject jSONObject3 = new JSONObject();
        boolean z = false;
        try {
            JSONObject[] jSONObjectArr = {jSONObject2, jSONObject};
            for (int i2 = 0; i2 < 2; i2++) {
                JSONObject jSONObject4 = jSONObjectArr[i2];
                if (jSONObject4 != null) {
                    Iterator<String> keys = jSONObject4.keys();
                    while (keys.hasNext()) {
                        String next = keys.next();
                        jSONObject3.put(next, jSONObject4.get(next));
                    }
                }
            }
        } catch (JSONException e2) {
            C4195m.m4816l(e2);
        }
        try {
            jSONObject3.put("external_info", str);
            jSONObject3.put("tid", m420a.f1262c);
            jSONObject3.put("user_agent", C1359d.m384d().m386b(c1373a, m420a));
            jSONObject3.put("has_alipay", C1383h.m447k(c1373a, m417a.f1259b, C1348e.f1168d));
            try {
                if (m417a.f1259b.getPackageManager().getPackageInfo("com.alipay.android.app", 128) != null) {
                    z = true;
                }
            } catch (PackageManager.NameNotFoundException unused) {
            }
            jSONObject3.put("has_msp_app", z);
            jSONObject3.put("app_key", "2014052600006128");
            jSONObject3.put("utdid", m417a.m419c());
            jSONObject3.put("new_client_key", m420a.f1263d);
            jSONObject3.put("pa", C1359d.m382a(m417a.f1259b));
        } catch (Throwable th) {
            C1353c.m363d(c1373a, "biz", "BodyErr", th);
            C4195m.m4816l(th);
        }
        return jSONObject3.toString();
    }

    /* renamed from: d */
    public String m402d(HashMap<String, String> hashMap, HashMap<String, String> hashMap2) {
        JSONObject jSONObject = new JSONObject();
        JSONObject jSONObject2 = new JSONObject();
        for (Map.Entry<String, String> entry : hashMap.entrySet()) {
            jSONObject2.put(entry.getKey(), entry.getValue());
        }
        JSONObject jSONObject3 = new JSONObject();
        for (Map.Entry<String, String> entry2 : hashMap2.entrySet()) {
            jSONObject3.put(entry2.getKey(), entry2.getValue());
        }
        jSONObject2.put(VideoListActivity.KEY_PARAMS, jSONObject3);
        jSONObject.put("data", jSONObject2);
        return jSONObject.toString();
    }

    /* renamed from: e */
    public Map<String, String> mo403e(boolean z, String str) {
        HashMap hashMap = new HashMap();
        hashMap.put("msp-gzip", String.valueOf(z));
        hashMap.put("Operation-Type", "alipay.msp.cashier.dispatch.bytes");
        hashMap.put("content-type", "application/octet-stream");
        hashMap.put("Version", "2.0");
        hashMap.put("AppId", "TAOBAO");
        String str2 = "";
        if (!TextUtils.isEmpty(str)) {
            String[] split = str.split("&");
            if (split.length != 0) {
                String str3 = null;
                String str4 = null;
                String str5 = null;
                String str6 = null;
                for (String str7 : split) {
                    if (TextUtils.isEmpty(str3)) {
                        str3 = !str7.contains("biz_type") ? null : C4195m.m4786S(str7);
                    }
                    if (TextUtils.isEmpty(str4)) {
                        str4 = !str7.contains("biz_no") ? null : C4195m.m4786S(str7);
                    }
                    if (TextUtils.isEmpty(str5)) {
                        str5 = (!str7.contains("trade_no") || str7.startsWith("out_trade_no")) ? null : C4195m.m4786S(str7);
                    }
                    if (TextUtils.isEmpty(str6)) {
                        str6 = !str7.contains("app_userid") ? null : C4195m.m4786S(str7);
                    }
                }
                StringBuilder sb = new StringBuilder();
                if (!TextUtils.isEmpty(str3)) {
                    sb.append("biz_type=" + str3 + ";");
                }
                if (!TextUtils.isEmpty(str4)) {
                    sb.append("biz_no=" + str4 + ";");
                }
                if (!TextUtils.isEmpty(str5)) {
                    sb.append("trade_no=" + str5 + ";");
                }
                if (!TextUtils.isEmpty(str6)) {
                    sb.append("app_userid=" + str6 + ";");
                }
                String sb2 = sb.toString();
                if (sb2.endsWith(";")) {
                    sb2 = sb2.substring(0, sb2.length() - 1);
                }
                str2 = sb2;
            }
        }
        hashMap.put("Msp-Param", str2);
        hashMap.put("des-mode", "CBC");
        return hashMap;
    }

    /* renamed from: f */
    public abstract JSONObject mo404f();

    /* renamed from: i */
    public String mo405i() {
        return "4.9.0";
    }

    /* renamed from: j */
    public String mo406j() {
        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("device", Build.MODEL);
        hashMap.put("namespace", "com.alipay.mobilecashier");
        hashMap.put("api_name", "com.alipay.mcpay");
        hashMap.put("api_version", mo405i());
        return m402d(hashMap, new HashMap<>());
    }
}
