package p005b.p085c.p088b.p092c;

import android.content.Context;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import p005b.p085c.p088b.p095f.C1363a;
import p005b.p085c.p088b.p095f.p096d.C1367b;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p085c.p088b.p098h.C1374b;
import p005b.p085c.p088b.p100j.C1382g;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.c.a */
/* loaded from: classes.dex */
public final class C1356a {

    /* renamed from: a */
    public static C1356a f1196a;

    /* renamed from: b */
    public int f1197b = 10000;

    /* renamed from: c */
    public boolean f1198c = false;

    /* renamed from: d */
    public String f1199d = "https://h5.m.taobao.com/mlapp/olist.html";

    /* renamed from: e */
    public int f1200e = 10;

    /* renamed from: f */
    public boolean f1201f = true;

    /* renamed from: g */
    public boolean f1202g = true;

    /* renamed from: h */
    public boolean f1203h = false;

    /* renamed from: i */
    public boolean f1204i = true;

    /* renamed from: j */
    public boolean f1205j = true;

    /* renamed from: k */
    public String f1206k = "";

    /* renamed from: l */
    public boolean f1207l = false;

    /* renamed from: m */
    public boolean f1208m = false;

    /* renamed from: n */
    public boolean f1209n = false;

    /* renamed from: o */
    public boolean f1210o = false;

    /* renamed from: p */
    public List<b> f1211p = null;

    /* renamed from: b.c.b.c.a$a */
    public class a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ C1373a f1212c;

        /* renamed from: e */
        public final /* synthetic */ Context f1213e;

        public a(C1373a c1373a, Context context) {
            this.f1212c = c1373a;
            this.f1213e = context;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                C1363a mo399a = new C1367b().mo399a(this.f1212c, this.f1213e, "");
                if (mo399a != null) {
                    C1356a c1356a = C1356a.this;
                    String str = mo399a.f1236b;
                    Objects.requireNonNull(c1356a);
                    if (!TextUtils.isEmpty(str)) {
                        try {
                            JSONObject optJSONObject = new JSONObject(str).optJSONObject("st_sdk_config");
                            if (optJSONObject != null) {
                                c1356a.m379c(optJSONObject);
                            } else {
                                C4195m.m4787T("DynCon", "empty config");
                            }
                        } catch (Throwable th) {
                            C4195m.m4816l(th);
                        }
                    }
                    C1356a c1356a2 = C1356a.this;
                    Objects.requireNonNull(c1356a2);
                    try {
                        C1382g.m435b(null, C1374b.m417a().f1259b, "alipay_cashier_dynamic_config", c1356a2.m380e().toString());
                    } catch (Exception e2) {
                        C4195m.m4816l(e2);
                    }
                }
            } catch (Throwable th2) {
                C4195m.m4816l(th2);
            }
        }
    }

    /* renamed from: b.c.b.c.a$b */
    public static final class b {

        /* renamed from: a */
        public final String f1215a;

        /* renamed from: b */
        public final int f1216b;

        /* renamed from: c */
        public final String f1217c;

        public b(String str, int i2, String str2) {
            this.f1215a = str;
            this.f1216b = i2;
            this.f1217c = str2;
        }

        /* renamed from: a */
        public static JSONObject m381a(b bVar) {
            if (bVar == null) {
                return null;
            }
            try {
                return new JSONObject().put("pn", bVar.f1215a).put("v", bVar.f1216b).put("pk", bVar.f1217c);
            } catch (JSONException e2) {
                C4195m.m4816l(e2);
                return null;
            }
        }

        public String toString() {
            return String.valueOf(m381a(this));
        }
    }

    /* renamed from: d */
    public static C1356a m376d() {
        if (f1196a == null) {
            C1356a c1356a = new C1356a();
            f1196a = c1356a;
            Objects.requireNonNull(c1356a);
            String m436c = C1382g.m436c(null, C1374b.m417a().f1259b, "alipay_cashier_dynamic_config", null);
            if (!TextUtils.isEmpty(m436c)) {
                try {
                    c1356a.m379c(new JSONObject(m436c));
                } catch (Throwable th) {
                    C4195m.m4816l(th);
                }
            }
        }
        return f1196a;
    }

    /* renamed from: a */
    public int m377a() {
        int i2 = this.f1197b;
        if (i2 < 1000 || i2 > 20000) {
            C4195m.m4787T("DynCon", "time(def) = 10000");
            return 10000;
        }
        StringBuilder m586H = C1499a.m586H("time = ");
        m586H.append(this.f1197b);
        C4195m.m4787T("DynCon", m586H.toString());
        return this.f1197b;
    }

    /* renamed from: b */
    public void m378b(C1373a c1373a, Context context) {
        new Thread(new a(c1373a, context)).start();
    }

    /* renamed from: c */
    public final void m379c(JSONObject jSONObject) {
        this.f1197b = jSONObject.optInt("timeout", 10000);
        this.f1198c = jSONObject.optBoolean("h5_port_degrade", false);
        this.f1199d = jSONObject.optString("tbreturl", "https://h5.m.taobao.com/mlapp/olist.html").trim();
        this.f1200e = jSONObject.optInt("configQueryInterval", 10);
        JSONArray optJSONArray = jSONObject.optJSONArray("launchAppSwitch");
        ArrayList arrayList = null;
        if (optJSONArray != null) {
            ArrayList arrayList2 = new ArrayList();
            int length = optJSONArray.length();
            for (int i2 = 0; i2 < length; i2++) {
                JSONObject optJSONObject = optJSONArray.optJSONObject(i2);
                b bVar = optJSONObject == null ? null : new b(optJSONObject.optString("pn"), optJSONObject.optInt("v", 0), optJSONObject.optString("pk"));
                if (bVar != null) {
                    arrayList2.add(bVar);
                }
            }
            arrayList = arrayList2;
        }
        this.f1211p = arrayList;
        this.f1201f = jSONObject.optBoolean("scheme_pay_2", true);
        this.f1202g = jSONObject.optBoolean("intercept_batch", true);
        this.f1203h = jSONObject.optBoolean("deg_log_mcgw", false);
        this.f1204i = jSONObject.optBoolean("deg_start_srv_first", true);
        this.f1205j = jSONObject.optBoolean("prev_jump_dual", true);
        this.f1206k = jSONObject.optString("use_sc_only", "");
        this.f1207l = jSONObject.optBoolean("bind_use_imp", false);
        this.f1208m = jSONObject.optBoolean("retry_bnd_once", false);
        this.f1209n = jSONObject.optBoolean("skip_trans", false);
        this.f1210o = jSONObject.optBoolean("up_before_pay", false);
    }

    /* renamed from: e */
    public final JSONObject m380e() {
        JSONArray jSONArray;
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("timeout", m377a());
        jSONObject.put("h5_port_degrade", this.f1198c);
        jSONObject.put("tbreturl", this.f1199d);
        jSONObject.put("configQueryInterval", this.f1200e);
        List<b> list = this.f1211p;
        if (list == null) {
            jSONArray = null;
        } else {
            JSONArray jSONArray2 = new JSONArray();
            Iterator<b> it = list.iterator();
            while (it.hasNext()) {
                jSONArray2.put(b.m381a(it.next()));
            }
            jSONArray = jSONArray2;
        }
        jSONObject.put("launchAppSwitch", jSONArray);
        jSONObject.put("scheme_pay_2", this.f1201f);
        jSONObject.put("intercept_batch", this.f1202g);
        jSONObject.put("deg_log_mcgw", this.f1203h);
        jSONObject.put("deg_start_srv_first", this.f1204i);
        jSONObject.put("prev_jump_dual", this.f1205j);
        jSONObject.put("use_sc_only", this.f1206k);
        jSONObject.put("bind_use_imp", this.f1207l);
        jSONObject.put("retry_bnd_once", this.f1208m);
        jSONObject.put("skip_trans", this.f1209n);
        jSONObject.put("up_before_pay", this.f1210o);
        return jSONObject;
    }
}
