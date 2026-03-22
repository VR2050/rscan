package p005b.p085c.p088b.p089a.p090h;

import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.a.h.a */
/* loaded from: classes.dex */
public final class C1351a {

    /* renamed from: a */
    public final LinkedHashMap<String, String> f1181a = new LinkedHashMap<>();

    public C1351a() {
    }

    /* renamed from: a */
    public String m359a() {
        try {
            JSONArray jSONArray = new JSONArray();
            for (Map.Entry<String, String> entry : this.f1181a.entrySet()) {
                JSONArray jSONArray2 = new JSONArray();
                jSONArray2.put(entry.getKey()).put(entry.getValue());
                jSONArray.put(jSONArray2);
            }
            return jSONArray.toString();
        } catch (Throwable th) {
            C4195m.m4816l(th);
            return new JSONArray().toString();
        }
    }

    public C1351a(String str) {
        try {
            JSONArray jSONArray = new JSONArray(str);
            for (int i2 = 0; i2 < jSONArray.length(); i2++) {
                JSONArray jSONArray2 = jSONArray.getJSONArray(i2);
                this.f1181a.put(jSONArray2.getString(0), jSONArray2.getString(1));
            }
        } catch (Throwable th) {
            C4195m.m4816l(th);
        }
    }
}
