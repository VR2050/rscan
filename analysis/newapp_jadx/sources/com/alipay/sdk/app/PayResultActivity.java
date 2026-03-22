package com.alipay.sdk.app;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.text.TextUtils;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import p005b.p085c.p088b.p089a.C1349f;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p098h.C1373a;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import tv.danmaku.ijk.media.player.IjkMediaCodecInfo;

/* loaded from: classes.dex */
public final class PayResultActivity extends Activity {

    /* renamed from: c */
    public static final HashMap<String, Object> f8666c = new HashMap<>();

    /* renamed from: e */
    public C1373a f8667e = null;

    /* renamed from: com.alipay.sdk.app.PayResultActivity$a */
    public static class RunnableC3192a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ Activity f8668c;

        public RunnableC3192a(Activity activity) {
            this.f8668c = activity;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f8668c.finish();
        }
    }

    /* renamed from: a */
    public static void m3833a(Activity activity, int i2) {
        new Handler().postDelayed(new RunnableC3192a(activity), i2);
    }

    /* renamed from: b */
    public static void m3834b(Activity activity, String str, String str2, String str3) {
        if (TextUtils.isEmpty(str2) || TextUtils.isEmpty(str3)) {
            return;
        }
        Intent intent = new Intent();
        try {
            intent.setPackage("hk.alipay.wallet");
            intent.setData(Uri.parse("alipayhk://platformapi/startApp?appId=20000125&schemePaySession=" + URLEncoder.encode(str, "UTF-8") + "&orderSuffix=" + URLEncoder.encode(str2, "UTF-8") + "&packageName=" + URLEncoder.encode(str3, "UTF-8") + "&externalPkgName=" + URLEncoder.encode(str3, "UTF-8")));
        } catch (UnsupportedEncodingException e2) {
            C4195m.m4816l(e2);
        }
        try {
            activity.startActivity(intent);
        } catch (Throwable unused) {
            activity.finish();
        }
    }

    /* renamed from: c */
    public static boolean m3835c(HashMap<String, Object> hashMap, String str) {
        Object obj;
        if (hashMap == null || str == null || (obj = hashMap.get(str)) == null) {
            return false;
        }
        synchronized (obj) {
            obj.notifyAll();
        }
        return true;
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        try {
            Intent intent = getIntent();
            if (!TextUtils.isEmpty(intent.getStringExtra("orderSuffix"))) {
                C4195m.f10933a = intent.getStringExtra("phonecashier.pay.hash");
                String stringExtra = intent.getStringExtra("orderSuffix");
                String stringExtra2 = intent.getStringExtra("externalPkgName");
                C1373a m415a = C1373a.a.m415a(intent);
                this.f8667e = m415a;
                if (m415a == null) {
                    finish();
                }
                m3834b(this, C4195m.f10933a, stringExtra, stringExtra2);
                m3833a(this, IjkMediaCodecInfo.RANK_SECURE);
                return;
            }
            if (this.f8667e == null) {
                finish();
            }
            String stringExtra3 = intent.getStringExtra("phonecashier.pay.result");
            int intExtra = intent.getIntExtra("phonecashier.pay.resultOrderHash", 0);
            if (intExtra != 0 && TextUtils.equals(C4195m.f10933a, String.valueOf(intExtra))) {
                if (TextUtils.isEmpty(stringExtra3)) {
                    String str = C4195m.f10933a;
                    C4195m.f10934b = C1349f.m357b();
                    m3835c(f8666c, str);
                } else {
                    String str2 = C4195m.f10933a;
                    C4195m.f10934b = stringExtra3;
                    m3835c(f8666c, str2);
                }
                C4195m.f10933a = "";
                m3833a(this, IjkMediaCodecInfo.RANK_SECURE);
                return;
            }
            C1353c.m362c(this.f8667e, "biz", "SchemePayWrongHashEx", "Expected " + C4195m.f10933a + ", got " + intExtra);
            String str3 = C4195m.f10933a;
            C4195m.f10934b = C1349f.m357b();
            m3835c(f8666c, str3);
            m3833a(this, IjkMediaCodecInfo.RANK_SECURE);
        } catch (Throwable unused) {
            finish();
        }
    }
}
