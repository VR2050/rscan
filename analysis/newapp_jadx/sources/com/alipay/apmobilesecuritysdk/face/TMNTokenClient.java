package com.alipay.apmobilesecuritysdk.face;

import android.content.Context;
import com.alipay.apmobilesecuritysdk.otherid.UtdidWrapper;
import com.alipay.apmobilesecuritysdk.p388a.C3167a;
import com.alipay.apmobilesecuritysdk.p393f.C3187b;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import java.util.HashMap;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class TMNTokenClient {

    /* renamed from: a */
    private static TMNTokenClient f8649a;

    /* renamed from: b */
    private Context f8650b;

    public interface InitResultListener {
        void onResult(String str, int i2);
    }

    private TMNTokenClient(Context context) {
        this.f8650b = null;
        if (context == null) {
            throw new IllegalArgumentException("TMNTokenClient initialization error: context is null.");
        }
        this.f8650b = context;
    }

    public static TMNTokenClient getInstance(Context context) {
        if (f8649a == null) {
            synchronized (TMNTokenClient.class) {
                if (f8649a == null) {
                    f8649a = new TMNTokenClient(context);
                }
            }
        }
        return f8649a;
    }

    public void intiToken(final String str, String str2, String str3, final InitResultListener initResultListener) {
        if (C4195m.m4822o(str) && initResultListener != null) {
            initResultListener.onResult("", 2);
        }
        if (C4195m.m4822o(str2) && initResultListener != null) {
            initResultListener.onResult("", 3);
        }
        final HashMap hashMap = new HashMap();
        hashMap.put("utdid", UtdidWrapper.getUtdid(this.f8650b));
        hashMap.put("tid", "");
        hashMap.put("userId", "");
        hashMap.put("appName", str);
        hashMap.put("appKeyClient", str2);
        hashMap.put("appchannel", "openapi");
        hashMap.put("sessionId", str3);
        hashMap.put("rpcVersion", MainMenusBean.TYPE_DAY_PICKS);
        C3187b.m3822a().m3825a(new Runnable() { // from class: com.alipay.apmobilesecuritysdk.face.TMNTokenClient.1
            @Override // java.lang.Runnable
            public void run() {
                int m3733a = new C3167a(TMNTokenClient.this.f8650b).m3733a(hashMap);
                InitResultListener initResultListener2 = initResultListener;
                if (initResultListener2 == null) {
                    return;
                }
                if (m3733a != 0) {
                    initResultListener2.onResult("", m3733a);
                } else {
                    initResultListener.onResult(C3167a.m3728a(TMNTokenClient.this.f8650b, str), 0);
                }
            }
        });
    }
}
