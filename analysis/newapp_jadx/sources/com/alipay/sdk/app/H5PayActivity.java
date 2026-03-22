package com.alipay.sdk.app;

import android.app.Activity;
import android.content.res.Configuration;
import android.os.Bundle;
import android.text.TextUtils;
import android.webkit.CookieManager;
import android.webkit.CookieSyncManager;
import com.alipay.sdk.widget.AbstractC3195c;
import com.alipay.sdk.widget.C3196d;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import java.util.regex.Pattern;
import p005b.p085c.p088b.p089a.C1349f;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p005b.p085c.p088b.p092c.C1356a;
import p005b.p085c.p088b.p098h.C1373a;
import p005b.p085c.p088b.p100j.C1380e;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class H5PayActivity extends Activity {

    /* renamed from: c */
    public AbstractC3195c f8659c;

    /* renamed from: e */
    public String f8660e;

    /* renamed from: f */
    public String f8661f;

    /* renamed from: g */
    public String f8662g;

    /* renamed from: h */
    public String f8663h;

    /* renamed from: i */
    public boolean f8664i;

    /* renamed from: j */
    public String f8665j;

    /* renamed from: a */
    public void mo3832a() {
        synchronized (C1380e.class) {
            try {
                C1380e.class.notify();
            } catch (Exception unused) {
            }
        }
    }

    @Override // android.app.Activity
    public void finish() {
        mo3832a();
        super.finish();
    }

    @Override // android.app.Activity
    public void onBackPressed() {
        AbstractC3195c abstractC3195c = this.f8659c;
        if (abstractC3195c == null) {
            finish();
            return;
        }
        if (abstractC3195c.m3847c()) {
            abstractC3195c.mo3846b();
            return;
        }
        if (!abstractC3195c.mo3846b()) {
            super.onBackPressed();
        }
        C1349f.f1170b = C1349f.m357b();
        finish();
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        try {
            super.requestWindowFeature(1);
        } catch (Throwable th) {
            C4195m.m4816l(th);
        }
        super.onCreate(bundle);
        try {
            C1373a m415a = C1373a.a.m415a(getIntent());
            if (m415a == null) {
                finish();
                return;
            }
            if (C1356a.m376d().f1198c) {
                setRequestedOrientation(3);
            } else {
                setRequestedOrientation(1);
            }
            try {
                Bundle extras = getIntent().getExtras();
                String string = extras.getString("url", null);
                this.f8660e = string;
                if (!Pattern.compile("^http(s)?://([a-z0-9_\\-]+\\.)*(alipaydev|alipay|taobao)\\.(com|net)(:\\d+)?(/.*)?$").matcher(string).matches()) {
                    finish();
                    return;
                }
                this.f8662g = extras.getString("cookie", null);
                this.f8661f = extras.getString("method", null);
                this.f8663h = extras.getString(VideoListActivity.KEY_TITLE, null);
                this.f8665j = extras.getString("version", "v1");
                this.f8664i = extras.getBoolean("backisexit", false);
                try {
                    C3196d c3196d = new C3196d(this, m415a, this.f8665j);
                    setContentView(c3196d);
                    String str = this.f8663h;
                    String str2 = this.f8661f;
                    boolean z = this.f8664i;
                    synchronized (c3196d) {
                        c3196d.f8686h = str2;
                        c3196d.f8690l.getTitle().setText(str);
                        c3196d.f8685g = z;
                    }
                    String str3 = this.f8660e;
                    String str4 = this.f8662g;
                    if (!TextUtils.isEmpty(str4)) {
                        CookieSyncManager.createInstance(c3196d.f8683e.getApplicationContext()).sync();
                        CookieManager.getInstance().setCookie(str3, str4);
                        CookieSyncManager.getInstance().sync();
                    }
                    c3196d.m3848d(this.f8660e);
                    this.f8659c = c3196d;
                } catch (Throwable th2) {
                    C1353c.m363d(m415a, "biz", "GetInstalledAppEx", th2);
                    finish();
                }
            } catch (Exception unused) {
                finish();
            }
        } catch (Exception unused2) {
            finish();
        }
    }

    @Override // android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        AbstractC3195c abstractC3195c = this.f8659c;
        if (abstractC3195c != null) {
            abstractC3195c.mo3845a();
        }
    }

    @Override // android.app.Activity
    public void setRequestedOrientation(int i2) {
        try {
            super.setRequestedOrientation(i2);
        } catch (Throwable th) {
            try {
                C1353c.m363d(C1373a.a.m415a(getIntent()), "biz", "H5PayDataAnalysisError", th);
            } catch (Throwable unused) {
            }
        }
    }
}
