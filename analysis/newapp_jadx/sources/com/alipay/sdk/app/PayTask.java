package com.alipay.sdk.app;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import org.json.JSONObject;
import p005b.p085c.p088b.p089a.C1347d;
import p005b.p085c.p088b.p089a.C1348e;
import p005b.p085c.p088b.p089a.C1349f;
import p005b.p085c.p088b.p089a.EnumC1350g;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p091b.C1355a;
import p005b.p085c.p088b.p092c.C1356a;
import p005b.p085c.p088b.p095f.p096d.C1370e;
import p005b.p085c.p088b.p097g.C1372b;
import p005b.p085c.p088b.p097g.EnumC1371a;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p085c.p088b.p098h.C1374b;
import p005b.p085c.p088b.p099i.C1375a;
import p005b.p085c.p088b.p100j.C1376a;
import p005b.p085c.p088b.p100j.C1380e;
import p005b.p085c.p088b.p100j.C1381f;
import p005b.p085c.p088b.p100j.C1382g;
import p005b.p085c.p088b.p100j.C1383h;
import p005b.p085c.p088b.p101k.C1385b;
import p005b.p085c.p088b.p101k.RunnableC1384a;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class PayTask {

    /* renamed from: a */
    public static long f8669a = 0;

    /* renamed from: b */
    public static long f8670b = -1;

    /* renamed from: c */
    public Activity f8671c;

    /* renamed from: d */
    public C1385b f8672d;

    /* renamed from: e */
    public Map<String, C3194b> f8673e = new HashMap();

    /* renamed from: com.alipay.sdk.app.PayTask$a */
    public class RunnableC3193a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ String f8674c;

        /* renamed from: e */
        public final /* synthetic */ boolean f8675e;

        /* renamed from: f */
        public final /* synthetic */ H5PayCallback f8676f;

        public RunnableC3193a(String str, boolean z, H5PayCallback h5PayCallback) {
            this.f8674c = str;
            this.f8675e = z;
            this.f8676f = h5PayCallback;
        }

        @Override // java.lang.Runnable
        public void run() {
            C1376a h5Pay = PayTask.this.h5Pay(new C1373a(PayTask.this.f8671c, this.f8674c, "payInterceptorWithUrl"), this.f8674c, this.f8675e);
            StringBuilder m586H = C1499a.m586H("inc finished: ");
            m586H.append(h5Pay.f1269b);
            C4195m.m4787T("mspl", m586H.toString());
            this.f8676f.onPayResult(h5Pay);
        }
    }

    /* renamed from: com.alipay.sdk.app.PayTask$b */
    public class C3194b {

        /* renamed from: a */
        public String f8678a = "";

        /* renamed from: b */
        public String f8679b = "";

        /* renamed from: c */
        public String f8680c = "";

        /* renamed from: d */
        public String f8681d = "";

        public C3194b(PayTask payTask, RunnableC3193a runnableC3193a) {
        }
    }

    public PayTask(Activity activity) {
        this.f8671c = activity;
        C1374b.m417a().m418b(this.f8671c);
        this.f8672d = new C1385b(activity, "去支付宝付款");
    }

    public static synchronized boolean fetchSdkConfig(Context context) {
        synchronized (PayTask.class) {
            try {
                C1374b.m417a().m418b(context);
                long elapsedRealtime = SystemClock.elapsedRealtime() / 1000;
                if (elapsedRealtime - f8669a < C1356a.m376d().f1200e) {
                    return false;
                }
                f8669a = elapsedRealtime;
                C1356a.m376d().m378b(null, context.getApplicationContext());
                return true;
            } catch (Exception e2) {
                C4195m.m4816l(e2);
                return false;
            }
        }
    }

    /* renamed from: g */
    public static final String m3836g(String... strArr) {
        for (String str : strArr) {
            if (!TextUtils.isEmpty(str)) {
                return str;
            }
        }
        return "";
    }

    /* renamed from: a */
    public final String m3837a(C1373a c1373a, C1372b c1372b) {
        String[] strArr = c1372b.f1246b;
        Intent intent = new Intent(this.f8671c, (Class<?>) H5PayActivity.class);
        Bundle bundle = new Bundle();
        bundle.putString("url", strArr[0]);
        if (strArr.length == 2) {
            bundle.putString("cookie", strArr[1]);
        }
        intent.putExtras(bundle);
        C1373a.a.m416b(c1373a, intent);
        this.f8671c.startActivity(intent);
        synchronized (C1380e.class) {
            try {
                C1380e.class.wait();
            } catch (InterruptedException e2) {
                C4195m.m4816l(e2);
                return C1349f.m357b();
            }
        }
        String str = C1349f.f1170b;
        return TextUtils.isEmpty(str) ? C1349f.m357b() : str;
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x0086, code lost:
    
        r0 = r4.f1246b;
        r11 = p005b.p085c.p088b.p089a.C1349f.m356a(java.lang.Integer.valueOf(r0[1]).intValue(), r0[0], p005b.p085c.p088b.p100j.C1383h.m444h(r10, r0[2]));
     */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String m3838b(p005b.p085c.p088b.p098h.C1373a r10, p005b.p085c.p088b.p097g.C1372b r11, java.lang.String r12) {
        /*
            Method dump skipped, instructions count: 255
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alipay.sdk.app.PayTask.m3838b(b.c.b.h.a, b.c.b.g.b, java.lang.String):java.lang.String");
    }

    /* renamed from: c */
    public final String m3839c(C1373a c1373a, String str) {
        ArrayList arrayList;
        String m3837a;
        showLoading();
        EnumC1350g enumC1350g = null;
        try {
            try {
                try {
                    JSONObject m395a = new C1370e().mo399a(c1373a, this.f8671c.getApplicationContext(), str).m395a();
                    String optString = m395a.optString("end_code", null);
                    List<C1372b> m407a = C1372b.m407a(m395a.optJSONObject("form").optJSONObject("onload"));
                    int i2 = 0;
                    while (true) {
                        arrayList = (ArrayList) m407a;
                        if (i2 >= arrayList.size()) {
                            break;
                        }
                        if (((C1372b) arrayList.get(i2)).f1245a == EnumC1371a.Update) {
                            C1372b.m408b((C1372b) arrayList.get(i2));
                        }
                        i2++;
                    }
                    m3843h(c1373a, m395a);
                    dismissLoading();
                    C1353c.m360a(this.f8671c, c1373a, str, c1373a.f1250d);
                    for (int i3 = 0; i3 < arrayList.size(); i3++) {
                        C1372b c1372b = (C1372b) arrayList.get(i3);
                        EnumC1371a enumC1371a = c1372b.f1245a;
                        if (enumC1371a == EnumC1371a.WapPay) {
                            m3837a = m3837a(c1373a, c1372b);
                        } else if (enumC1371a == EnumC1371a.OpenWeb) {
                            m3837a = m3838b(c1373a, c1372b, optString);
                        }
                        dismissLoading();
                        C1353c.m360a(this.f8671c, c1373a, str, c1373a.f1250d);
                        return m3837a;
                    }
                } catch (IOException e2) {
                    EnumC1350g m358a = EnumC1350g.m358a(6002);
                    C1353c.m365f(c1373a, "net", e2);
                    dismissLoading();
                    C1353c.m360a(this.f8671c, c1373a, str, c1373a.f1250d);
                    enumC1350g = m358a;
                }
            } catch (Throwable th) {
                C4195m.m4816l(th);
                C1353c.m363d(c1373a, "biz", "H5PayDataAnalysisError", th);
            }
            dismissLoading();
            C1353c.m360a(this.f8671c, c1373a, str, c1373a.f1250d);
            if (enumC1350g == null) {
                enumC1350g = EnumC1350g.m358a(4000);
            }
            return C1349f.m356a(enumC1350g.f1179l, enumC1350g.f1180m, "");
        } catch (Throwable th2) {
            dismissLoading();
            C1353c.m360a(this.f8671c, c1373a, str, c1373a.f1250d);
            throw th2;
        }
    }

    /* renamed from: d */
    public final synchronized String m3840d(C1373a c1373a, String str, boolean z) {
        boolean z2;
        Context applicationContext;
        String str2;
        long elapsedRealtime = SystemClock.elapsedRealtime();
        if (elapsedRealtime - f8670b >= 3000) {
            f8670b = elapsedRealtime;
            z2 = false;
        } else {
            z2 = true;
        }
        if (z2) {
            C1353c.m362c(c1373a, "biz", "RepPay", "");
            EnumC1350g m358a = EnumC1350g.m358a(5000);
            return C1349f.m356a(m358a.f1179l, m358a.f1180m, "");
        }
        if (z) {
            showLoading();
        }
        if (str.contains("payment_inst=")) {
            String substring = str.substring(str.indexOf("payment_inst=") + 13);
            int indexOf = substring.indexOf(38);
            if (indexOf > 0) {
                substring = substring.substring(0, indexOf);
            }
            C1348e.m355a(substring.replaceAll("\"", "").toLowerCase(Locale.getDefault()).replaceAll("alipay", ""));
        } else {
            C1348e.m355a("");
        }
        if (str.contains("service=alipay.acquire.mr.ord.createandpay")) {
            C1355a.f1195b = true;
        }
        if (C1355a.f1195b) {
            if (str.startsWith("https://wappaygw.alipay.com/home/exterfaceAssign.htm?")) {
                str = str.substring(str.indexOf("https://wappaygw.alipay.com/home/exterfaceAssign.htm?") + 53);
            } else if (str.startsWith("https://mclient.alipay.com/home/exterfaceAssign.htm?")) {
                str = str.substring(str.indexOf("https://mclient.alipay.com/home/exterfaceAssign.htm?") + 52);
            }
        }
        String str3 = "";
        try {
            C4195m.m4787T("mspl", "pay prepared: " + str);
            str3 = m3841e(str, c1373a);
            C4195m.m4787T("mspl", "pay raw result: " + str3);
            C1381f.m433e(c1373a, this.f8671c.getApplicationContext(), str3);
            C1353c.m367h(c1373a, "biz", "PgReturn", "" + SystemClock.elapsedRealtime());
            C1353c.m367h(c1373a, "biz", "PgReturnV", C1381f.m430b(str3, "resultStatus") + "|" + C1381f.m430b(str3, "memo"));
            if (!C1356a.m376d().f1210o) {
                C1356a.m376d().m378b(c1373a, this.f8671c.getApplicationContext());
            }
            dismissLoading();
            applicationContext = this.f8671c.getApplicationContext();
            str2 = c1373a.f1250d;
        } catch (Throwable th) {
            try {
                str3 = C1349f.m357b();
                C4195m.m4816l(th);
                C1353c.m367h(c1373a, "biz", "PgReturn", "" + SystemClock.elapsedRealtime());
                C1353c.m367h(c1373a, "biz", "PgReturnV", C1381f.m430b(str3, "resultStatus") + "|" + C1381f.m430b(str3, "memo"));
                if (!C1356a.m376d().f1210o) {
                    C1356a.m376d().m378b(c1373a, this.f8671c.getApplicationContext());
                }
                dismissLoading();
                applicationContext = this.f8671c.getApplicationContext();
                str2 = c1373a.f1250d;
            } catch (Throwable th2) {
                C1353c.m367h(c1373a, "biz", "PgReturn", "" + SystemClock.elapsedRealtime());
                C1353c.m367h(c1373a, "biz", "PgReturnV", C1381f.m430b(str3, "resultStatus") + "|" + C1381f.m430b(str3, "memo"));
                if (!C1356a.m376d().f1210o) {
                    C1356a.m376d().m378b(c1373a, this.f8671c.getApplicationContext());
                }
                dismissLoading();
                C1353c.m366g(this.f8671c.getApplicationContext(), c1373a, str, c1373a.f1250d);
                throw th2;
            }
        }
        C1353c.m366g(applicationContext, c1373a, str, str2);
        C4195m.m4787T("mspl", "pay returning: " + str3);
        return str3;
    }

    public void dismissLoading() {
        C1385b c1385b = this.f8672d;
        if (c1385b != null) {
            c1385b.m455a();
            this.f8672d = null;
        }
    }

    /* renamed from: e */
    public final String m3841e(String str, C1373a c1373a) {
        String m410a = c1373a.m410a(str);
        if (m410a.contains("paymethod=\"expressGateway\"")) {
            return m3839c(c1373a, m410a);
        }
        List<C1356a.b> list = C1356a.m376d().f1211p;
        Objects.requireNonNull(C1356a.m376d());
        List<C1356a.b> list2 = C1348e.f1168d;
        if (!C1383h.m447k(c1373a, this.f8671c, list2)) {
            C1353c.m361b(c1373a, "biz", "LogCalledH5");
            return m3839c(c1373a, m410a);
        }
        C1380e c1380e = new C1380e(this.f8671c, c1373a, new C1347d(this));
        C4195m.m4787T("mspl", "pay inner started: " + m410a);
        String m428b = c1380e.m428b(m410a);
        C4195m.m4787T("mspl", "pay inner raw result: " + m428b);
        c1380e.f1293a = null;
        c1380e.f1297e = null;
        if (TextUtils.equals(m428b, "failed") || TextUtils.equals(m428b, "scheme_failed")) {
            C1353c.m361b(c1373a, "biz", "LogBindCalledH5");
            return m3839c(c1373a, m410a);
        }
        if (TextUtils.isEmpty(m428b)) {
            return C1349f.m357b();
        }
        if (m428b.contains("{\"isLogin\":\"false\"}")) {
            C1353c.m361b(c1373a, "biz", "LogHkLoginByIntent");
            Activity activity = this.f8671c;
            C1383h.b m437a = C1383h.m437a(c1373a, activity, list2);
            if (m437a != null && !m437a.m454b(c1373a) && !m437a.m453a() && TextUtils.equals(m437a.f1305a.packageName, "hk.alipay.wallet")) {
                C4195m.m4787T("mspl", "PayTask not_login");
                String valueOf = String.valueOf(m410a.hashCode());
                Object obj = new Object();
                HashMap<String, Object> hashMap = PayResultActivity.f8666c;
                hashMap.put(valueOf, obj);
                Intent intent = new Intent(activity, (Class<?>) PayResultActivity.class);
                intent.putExtra("orderSuffix", m410a);
                intent.putExtra("externalPkgName", activity.getPackageName());
                intent.putExtra("phonecashier.pay.hash", valueOf);
                C1373a.a.m416b(c1373a, intent);
                activity.startActivity(intent);
                synchronized (hashMap.get(valueOf)) {
                    try {
                        C4195m.m4787T("mspl", "PayTask wait");
                        hashMap.get(valueOf).wait();
                    } catch (InterruptedException unused) {
                        C4195m.m4787T("mspl", "PayTask interrupted");
                        m428b = C1349f.m357b();
                    }
                }
                m428b = C4195m.f10934b;
                C4195m.m4787T("mspl", "PayTask ret: " + m428b);
            }
        }
        return m428b;
    }

    /* renamed from: f */
    public final String m3842f(String str, Map<String, String> map) {
        boolean equals = "9000".equals(map.get("resultStatus"));
        String str2 = map.get("result");
        C3194b remove = this.f8673e.remove(str);
        String[] strArr = new String[2];
        strArr[0] = remove != null ? remove.f8680c : "";
        strArr[1] = remove != null ? remove.f8681d : "";
        m3836g(strArr);
        if (map.containsKey("callBackUrl")) {
            return map.get("callBackUrl");
        }
        if (str2.length() > 15) {
            String m3836g = m3836g(C1383h.m441e("&callBackUrl=\"", "\"", str2), C1383h.m441e("&call_back_url=\"", "\"", str2), C1383h.m441e("&return_url=\"", "\"", str2), URLDecoder.decode(C1383h.m441e("&return_url=", "&", str2), "utf-8"), URLDecoder.decode(C1383h.m441e("&callBackUrl=", "&", str2), "utf-8"), C1383h.m441e("call_back_url=\"", "\"", str2));
            if (!TextUtils.isEmpty(m3836g)) {
                return m3836g;
            }
        }
        if (remove != null) {
            String str3 = equals ? remove.f8678a : remove.f8679b;
            if (!TextUtils.isEmpty(str3)) {
                return str3;
            }
        }
        return remove != null ? C1356a.m376d().f1199d : "";
    }

    public synchronized String fetchOrderInfoFromH5PayUrl(String str) {
        try {
            if (!TextUtils.isEmpty(str)) {
                String trim = str.trim();
                if (trim.startsWith("https://wappaygw.alipay.com/service/rest.htm") || trim.startsWith("http://wappaygw.alipay.com/service/rest.htm")) {
                    String trim2 = trim.replaceFirst("(http|https)://wappaygw.alipay.com/service/rest.htm\\?", "").trim();
                    if (!TextUtils.isEmpty(trim2)) {
                        return "_input_charset=\"utf-8\"&ordertoken=\"" + C1383h.m441e("<request_token>", "</request_token>", (String) ((HashMap) C1383h.m445i(trim2)).get("req_data")) + "\"&pay_channel_id=\"alipay_sdk\"&bizcontext=\"" + new C1373a(this.f8671c, "", "").m411b("sc", "h5tonative") + "\"";
                    }
                }
                if (trim.startsWith("https://mclient.alipay.com/service/rest.htm") || trim.startsWith("http://mclient.alipay.com/service/rest.htm")) {
                    String trim3 = trim.replaceFirst("(http|https)://mclient.alipay.com/service/rest.htm\\?", "").trim();
                    if (!TextUtils.isEmpty(trim3)) {
                        return "_input_charset=\"utf-8\"&ordertoken=\"" + C1383h.m441e("<request_token>", "</request_token>", (String) ((HashMap) C1383h.m445i(trim3)).get("req_data")) + "\"&pay_channel_id=\"alipay_sdk\"&bizcontext=\"" + new C1373a(this.f8671c, "", "").m411b("sc", "h5tonative") + "\"";
                    }
                }
                if ((trim.startsWith("https://mclient.alipay.com/home/exterfaceAssign.htm") || trim.startsWith("http://mclient.alipay.com/home/exterfaceAssign.htm")) && ((trim.contains("alipay.wap.create.direct.pay.by.user") || trim.contains("create_forex_trade_wap")) && !TextUtils.isEmpty(trim.replaceFirst("(http|https)://mclient.alipay.com/home/exterfaceAssign.htm\\?", "").trim()))) {
                    C1373a c1373a = new C1373a(this.f8671c, "", "");
                    JSONObject jSONObject = new JSONObject();
                    jSONObject.put("url", str);
                    jSONObject.put("bizcontext", c1373a.m411b("sc", "h5tonative"));
                    return "new_external_info==" + jSONObject.toString();
                }
                if (Pattern.compile("^(http|https)://(maliprod\\.alipay\\.com/w/trade_pay\\.do.?|mali\\.alipay\\.com/w/trade_pay\\.do.?|mclient\\.alipay\\.com/w/trade_pay\\.do.?)").matcher(str).find()) {
                    String m441e = C1383h.m441e("?", "", str);
                    if (!TextUtils.isEmpty(m441e)) {
                        Map<String, String> m445i = C1383h.m445i(m441e);
                        StringBuilder sb = new StringBuilder();
                        if (m3844i(false, true, "trade_no", sb, m445i, "trade_no", "alipay_trade_no")) {
                            m3844i(true, false, "pay_phase_id", sb, m445i, "payPhaseId", "pay_phase_id", "out_relation_id");
                            sb.append("&biz_sub_type=\"TRADE\"");
                            sb.append("&biz_type=\"trade\"");
                            HashMap hashMap = (HashMap) m445i;
                            String str2 = (String) hashMap.get("app_name");
                            if (TextUtils.isEmpty(str2) && !TextUtils.isEmpty((CharSequence) hashMap.get("cid"))) {
                                str2 = "ali1688";
                            } else if (TextUtils.isEmpty(str2) && (!TextUtils.isEmpty((CharSequence) hashMap.get("sid")) || !TextUtils.isEmpty((CharSequence) hashMap.get("s_id")))) {
                                str2 = "tb";
                            }
                            sb.append("&app_name=\"" + str2 + "\"");
                            if (!m3844i(true, true, "extern_token", sb, m445i, "extern_token", "cid", "sid", "s_id")) {
                                return "";
                            }
                            m3844i(true, false, "appenv", sb, m445i, "appenv");
                            sb.append("&pay_channel_id=\"alipay_sdk\"");
                            C3194b c3194b = new C3194b(this, null);
                            c3194b.f8678a = (String) hashMap.get("return_url");
                            c3194b.f8679b = (String) hashMap.get("show_url");
                            c3194b.f8680c = (String) hashMap.get("pay_order_id");
                            String str3 = sb.toString() + "&bizcontext=\"" + new C1373a(this.f8671c, "", "").m411b("sc", "h5tonative") + "\"";
                            this.f8673e.put(str3, c3194b);
                            return str3;
                        }
                    }
                }
                if (trim.startsWith("https://mclient.alipay.com/cashier/mobilepay.htm") || trim.startsWith("http://mclient.alipay.com/cashier/mobilepay.htm")) {
                    String m411b = new C1373a(this.f8671c, "", "").m411b("sc", "h5tonative");
                    JSONObject jSONObject2 = new JSONObject();
                    jSONObject2.put("url", trim);
                    jSONObject2.put("bizcontext", m411b);
                    return String.format("new_external_info==%s", jSONObject2.toString());
                }
                if (C1356a.m376d().f1202g && Pattern.compile("^https?://(maliprod\\.alipay\\.com|mali\\.alipay\\.com)/batch_payment\\.do\\?").matcher(trim).find()) {
                    Uri parse = Uri.parse(trim);
                    String queryParameter = parse.getQueryParameter("return_url");
                    String queryParameter2 = parse.getQueryParameter("show_url");
                    String queryParameter3 = parse.getQueryParameter("pay_order_id");
                    String m3836g = m3836g(parse.getQueryParameter("trade_nos"), parse.getQueryParameter("alipay_trade_no"));
                    String m3836g2 = m3836g(parse.getQueryParameter("payPhaseId"), parse.getQueryParameter("pay_phase_id"), parse.getQueryParameter("out_relation_id"));
                    String[] strArr = new String[4];
                    strArr[0] = parse.getQueryParameter("app_name");
                    strArr[1] = !TextUtils.isEmpty(parse.getQueryParameter("cid")) ? "ali1688" : "";
                    strArr[2] = !TextUtils.isEmpty(parse.getQueryParameter("sid")) ? "tb" : "";
                    strArr[3] = !TextUtils.isEmpty(parse.getQueryParameter("s_id")) ? "tb" : "";
                    String m3836g3 = m3836g(strArr);
                    String m3836g4 = m3836g(parse.getQueryParameter("extern_token"), parse.getQueryParameter("cid"), parse.getQueryParameter("sid"), parse.getQueryParameter("s_id"));
                    String m3836g5 = m3836g(parse.getQueryParameter("appenv"));
                    if (!TextUtils.isEmpty(m3836g) && !TextUtils.isEmpty(m3836g3) && !TextUtils.isEmpty(m3836g4)) {
                        String format = String.format("trade_no=\"%s\"&pay_phase_id=\"%s\"&biz_type=\"trade\"&biz_sub_type=\"TRADE\"&app_name=\"%s\"&extern_token=\"%s\"&appenv=\"%s\"&pay_channel_id=\"alipay_sdk\"&bizcontext=\"%s\"", m3836g, m3836g2, m3836g3, m3836g4, m3836g5, new C1373a(this.f8671c, "", "").m411b("sc", "h5tonative"));
                        C3194b c3194b2 = new C3194b(this, null);
                        c3194b2.f8678a = queryParameter;
                        c3194b2.f8679b = queryParameter2;
                        c3194b2.f8680c = queryParameter3;
                        c3194b2.f8681d = m3836g;
                        this.f8673e.put(format, c3194b2);
                        return format;
                    }
                }
            }
        } catch (Throwable th) {
            C4195m.m4816l(th);
        }
        return "";
    }

    public synchronized String fetchTradeToken() {
        String m436c;
        m436c = C1382g.m436c(new C1373a(this.f8671c, "", "fetchTradeToken"), this.f8671c.getApplicationContext(), "pref_trade_token", "");
        C4195m.m4787T("mspl", "get trade token: " + m436c);
        return m436c;
    }

    public String getVersion() {
        return "15.7.7";
    }

    /* renamed from: h */
    public final void m3843h(C1373a c1373a, JSONObject jSONObject) {
        try {
            String optString = jSONObject.optString("tid");
            String optString2 = jSONObject.optString("client_key");
            if (TextUtils.isEmpty(optString) || TextUtils.isEmpty(optString2)) {
                return;
            }
            C1375a.m420a(C1374b.m417a().f1259b).m421b(optString, optString2);
        } catch (Throwable th) {
            C1353c.m363d(c1373a, "biz", "ParserTidClientKeyEx", th);
        }
    }

    public synchronized C1376a h5Pay(C1373a c1373a, String str, boolean z) {
        C1376a c1376a;
        c1376a = new C1376a();
        try {
            String[] split = m3840d(c1373a, str, z).split(";");
            HashMap hashMap = new HashMap();
            for (String str2 : split) {
                int indexOf = str2.indexOf("={");
                if (indexOf >= 0) {
                    String substring = str2.substring(0, indexOf);
                    String str3 = substring + "={";
                    hashMap.put(substring, str2.substring(str3.length() + str2.indexOf(str3), str2.lastIndexOf("}")));
                }
            }
            if (hashMap.containsKey("resultStatus")) {
                c1376a.f1269b = (String) hashMap.get("resultStatus");
            }
            String m3842f = m3842f(str, hashMap);
            c1376a.f1268a = m3842f;
            if (TextUtils.isEmpty(m3842f)) {
                C1353c.m362c(c1373a, "biz", "H5CbUrlEmpty", "");
            }
        } catch (Throwable th) {
            C1353c.m363d(c1373a, "biz", "H5CbEx", th);
            C4195m.m4816l(th);
        }
        return c1376a;
    }

    /* renamed from: i */
    public final boolean m3844i(boolean z, boolean z2, String str, StringBuilder sb, Map<String, String> map, String... strArr) {
        String str2;
        int length = strArr.length;
        int i2 = 0;
        while (true) {
            if (i2 >= length) {
                str2 = "";
                break;
            }
            String str3 = strArr[i2];
            if (!TextUtils.isEmpty(map.get(str3))) {
                str2 = map.get(str3);
                break;
            }
            i2++;
        }
        if (TextUtils.isEmpty(str2)) {
            return !z2;
        }
        if (!z) {
            C1499a.m608b0(sb, str, "=\"", str2, "\"");
            return true;
        }
        C1499a.m608b0(sb, "&", str, "=\"", str2);
        sb.append("\"");
        return true;
    }

    public synchronized String pay(String str, boolean z) {
        return m3840d(new C1373a(this.f8671c, str, "pay"), str, z);
    }

    public synchronized boolean payInterceptorWithUrl(String str, boolean z, H5PayCallback h5PayCallback) {
        String fetchOrderInfoFromH5PayUrl;
        fetchOrderInfoFromH5PayUrl = fetchOrderInfoFromH5PayUrl(str);
        if (!TextUtils.isEmpty(fetchOrderInfoFromH5PayUrl)) {
            C4195m.m4787T("mspl", "intercepted: " + fetchOrderInfoFromH5PayUrl);
            new Thread(new RunnableC3193a(fetchOrderInfoFromH5PayUrl, z, h5PayCallback)).start();
        }
        return !TextUtils.isEmpty(fetchOrderInfoFromH5PayUrl);
    }

    public synchronized Map<String, String> payV2(String str, boolean z) {
        C1373a c1373a;
        c1373a = new C1373a(this.f8671c, str, "payV2");
        return C1381f.m431c(c1373a, m3840d(c1373a, str, z));
    }

    public void showLoading() {
        Activity activity;
        C1385b c1385b = this.f8672d;
        if (c1385b == null || (activity = c1385b.f1310b) == null) {
            return;
        }
        activity.runOnUiThread(new RunnableC1384a(c1385b));
    }
}
