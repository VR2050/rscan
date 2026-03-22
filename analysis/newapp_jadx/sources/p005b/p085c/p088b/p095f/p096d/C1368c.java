package p005b.p085c.p088b.p095f.p096d;

import android.content.Context;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;
import p005b.p085c.p088b.p095f.AbstractC1365c;
import p005b.p085c.p088b.p095f.C1363a;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.c.b.f.d.c */
/* loaded from: classes.dex */
public class C1368c extends AbstractC1365c {
    @Override // p005b.p085c.p088b.p095f.AbstractC1365c
    /* renamed from: a */
    public C1363a mo399a(C1373a c1373a, Context context, String str) {
        return m400b(c1373a, context, str, "https://mcgw.alipay.com/sdklog.do", true);
    }

    @Override // p005b.p085c.p088b.p095f.AbstractC1365c
    /* renamed from: c */
    public String mo401c(C1373a c1373a, String str, JSONObject jSONObject) {
        return str;
    }

    @Override // p005b.p085c.p088b.p095f.AbstractC1365c
    /* renamed from: e */
    public Map<String, String> mo403e(boolean z, String str) {
        HashMap hashMap = new HashMap();
        hashMap.put("msp-gzip", String.valueOf(z));
        hashMap.put("content-type", "application/octet-stream");
        hashMap.put("des-mode", "CBC");
        return hashMap;
    }

    @Override // p005b.p085c.p088b.p095f.AbstractC1365c
    /* renamed from: f */
    public JSONObject mo404f() {
        return null;
    }

    @Override // p005b.p085c.p088b.p095f.AbstractC1365c
    /* renamed from: j */
    public String mo406j() {
        HashMap<String, String> m596R = C1499a.m596R("api_name", "/sdk/log", "api_version", "1.0.0");
        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("log_v", "1.0");
        return m402d(m596R, hashMap);
    }
}
