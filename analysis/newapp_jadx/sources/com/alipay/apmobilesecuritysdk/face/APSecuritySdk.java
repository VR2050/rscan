package com.alipay.apmobilesecuritysdk.face;

import android.content.Context;
import com.alipay.apmobilesecuritysdk.otherid.UmidSdkWrapper;
import com.alipay.apmobilesecuritysdk.otherid.UtdidWrapper;
import com.alipay.apmobilesecuritysdk.p388a.C3167a;
import com.alipay.apmobilesecuritysdk.p389b.C3168a;
import com.alipay.apmobilesecuritysdk.p392e.C3177a;
import com.alipay.apmobilesecuritysdk.p392e.C3180d;
import com.alipay.apmobilesecuritysdk.p392e.C3183g;
import com.alipay.apmobilesecuritysdk.p392e.C3184h;
import com.alipay.apmobilesecuritysdk.p392e.C3185i;
import com.alipay.apmobilesecuritysdk.p393f.C3187b;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import java.util.HashMap;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class APSecuritySdk {

    /* renamed from: a */
    private static APSecuritySdk f8642a;

    /* renamed from: c */
    private static Object f8643c = new Object();

    /* renamed from: b */
    private Context f8644b;

    public interface InitResultListener {
        void onResult(TokenResult tokenResult);
    }

    public class TokenResult {
        public String apdid;
        public String apdidToken;
        public String clientKey;
        public String umidToken;

        public TokenResult() {
        }
    }

    private APSecuritySdk(Context context) {
        this.f8644b = context;
    }

    public static APSecuritySdk getInstance(Context context) {
        if (f8642a == null) {
            synchronized (f8643c) {
                if (f8642a == null) {
                    f8642a = new APSecuritySdk(context);
                }
            }
        }
        return f8642a;
    }

    public static String getUtdid(Context context) {
        return UtdidWrapper.getUtdid(context);
    }

    public String getApdidToken() {
        String m3728a = C3167a.m3728a(this.f8644b, "");
        if (C4195m.m4822o(m3728a)) {
            initToken(0, new HashMap(), null);
        }
        return m3728a;
    }

    public String getSdkName() {
        return "APPSecuritySDK-ALIPAYSDK";
    }

    public String getSdkVersion() {
        return "3.4.0.201910161639";
    }

    public synchronized TokenResult getTokenResult() {
        TokenResult tokenResult;
        tokenResult = new TokenResult();
        try {
            tokenResult.apdidToken = C3167a.m3728a(this.f8644b, "");
            tokenResult.clientKey = C3184h.m3796f(this.f8644b);
            tokenResult.apdid = C3167a.m3727a(this.f8644b);
            tokenResult.umidToken = UmidSdkWrapper.getSecurityToken(this.f8644b);
            if (C4195m.m4822o(tokenResult.apdid) || C4195m.m4822o(tokenResult.apdidToken) || C4195m.m4822o(tokenResult.clientKey)) {
                initToken(0, new HashMap(), null);
            }
        } catch (Throwable unused) {
        }
        return tokenResult;
    }

    public void initToken(int i2, Map<String, String> map, final InitResultListener initResultListener) {
        C3168a.m3734a().m3735a(i2);
        String m3788b = C3184h.m3788b(this.f8644b);
        String m3737c = C3168a.m3734a().m3737c();
        if (C4195m.m4840x(m3788b) && !C4195m.m4824p(m3788b, m3737c)) {
            C3177a.m3756a(this.f8644b);
            C3180d.m3763a(this.f8644b);
            C3183g.m3781a(this.f8644b);
            C3185i.m3817h();
        }
        if (!C4195m.m4824p(m3788b, m3737c)) {
            C3184h.m3790c(this.f8644b, m3737c);
        }
        String m4808h = C4195m.m4808h(map, "utdid", "");
        String m4808h2 = C4195m.m4808h(map, "tid", "");
        String m4808h3 = C4195m.m4808h(map, "userId", "");
        if (C4195m.m4822o(m4808h)) {
            m4808h = UtdidWrapper.getUtdid(this.f8644b);
        }
        final HashMap m596R = C1499a.m596R("utdid", m4808h, "tid", m4808h2);
        m596R.put("userId", m4808h3);
        m596R.put("appName", "");
        m596R.put("appKeyClient", "");
        m596R.put("appchannel", "");
        m596R.put("rpcVersion", MainMenusBean.TYPE_DAY_PICKS);
        C3187b.m3822a().m3825a(new Runnable() { // from class: com.alipay.apmobilesecuritysdk.face.APSecuritySdk.1
            @Override // java.lang.Runnable
            public void run() {
                new C3167a(APSecuritySdk.this.f8644b).m3733a(m596R);
                InitResultListener initResultListener2 = initResultListener;
                if (initResultListener2 != null) {
                    initResultListener2.onResult(APSecuritySdk.this.getTokenResult());
                }
            }
        });
    }
}
