package p005b.p085c.p088b.p095f.p096d;

import android.content.Context;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;
import p005b.p085c.p088b.p094e.C1362a;
import p005b.p085c.p088b.p095f.AbstractC1365c;
import p005b.p085c.p088b.p095f.C1363a;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p085c.p088b.p098h.C1374b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.f.d.d */
/* loaded from: classes.dex */
public class C1369d extends AbstractC1365c {
    @Override // p005b.p085c.p088b.p095f.AbstractC1365c
    /* renamed from: a */
    public C1363a mo399a(C1373a c1373a, Context context, String str) {
        C4195m.m4787T("mspl", "mdap post");
        byte[] m4828r = C4195m.m4828r(str.getBytes(Charset.forName("UTF-8")));
        HashMap hashMap = new HashMap();
        hashMap.put("utdId", C1374b.m417a().m419c());
        hashMap.put("logHeader", "RAW");
        hashMap.put("bizCode", "alipaysdk");
        hashMap.put("productId", "alipaysdk_android");
        hashMap.put("Content-Encoding", "Gzip");
        hashMap.put("productVersion", "15.7.7");
        C1362a.b m393a = C1362a.m393a(context, new C1362a.a("https://loggw-exsdk.alipay.com/loggw/logUpload.do", hashMap, m4828r));
        C4195m.m4787T("mspl", "mdap got " + m393a);
        if (m393a == null) {
            throw new RuntimeException("Response is null");
        }
        boolean m398h = AbstractC1365c.m398h(m393a);
        try {
            byte[] bArr = m393a.f1234b;
            if (m398h) {
                bArr = C4195m.m4842y(bArr);
            }
            return new C1363a("", new String(bArr, Charset.forName("UTF-8")));
        } catch (Exception e2) {
            C4195m.m4816l(e2);
            return null;
        }
    }

    @Override // p005b.p085c.p088b.p095f.AbstractC1365c
    /* renamed from: c */
    public String mo401c(C1373a c1373a, String str, JSONObject jSONObject) {
        return str;
    }

    @Override // p005b.p085c.p088b.p095f.AbstractC1365c
    /* renamed from: e */
    public Map<String, String> mo403e(boolean z, String str) {
        return new HashMap();
    }

    @Override // p005b.p085c.p088b.p095f.AbstractC1365c
    /* renamed from: f */
    public JSONObject mo404f() {
        return null;
    }
}
