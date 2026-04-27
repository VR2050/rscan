package io.openinstall.sdk;

import android.content.Context;
import android.text.TextUtils;
import com.fm.openinstall.Configuration;

/* JADX INFO: loaded from: classes3.dex */
public class q extends cw {
    private final Configuration a;
    private final Context b;

    public q(Context context, Configuration configuration) {
        this.b = context;
        this.a = configuration;
    }

    private String a(String str) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        for (int i = 0; i < str.length(); i++) {
            char cCharAt = str.charAt(i);
            if (cCharAt != '0' && cCharAt != '-') {
                return str;
            }
        }
        return null;
    }

    @Override // io.openinstall.sdk.cw
    public boolean a() {
        return !Configuration.isPresent(this.a.getOaid());
    }

    @Override // io.openinstall.sdk.cw
    protected String b() {
        return "oa";
    }

    @Override // io.openinstall.sdk.cw
    protected String c() {
        return "effj";
    }

    @Override // io.openinstall.sdk.cw
    protected String d() {
        String strA;
        if (Configuration.isPresent(this.a.getOaid())) {
            strA = this.a.getOaid();
        } else {
            try {
                strA = aa.a(this.b).a(this.b);
            } catch (Exception e) {
                if (ec.a) {
                    ec.c("getOAID throw exception : %s", e.getMessage());
                }
                strA = null;
            }
        }
        return a(strA);
    }
}
