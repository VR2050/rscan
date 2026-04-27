package io.openinstall.sdk;

import com.fm.openinstall.Configuration;

/* JADX INFO: loaded from: classes3.dex */
public class n extends cw {
    private final Configuration a;
    private final s b;

    public n(Configuration configuration, s sVar) {
        this.a = configuration;
        this.b = sVar;
    }

    @Override // io.openinstall.sdk.cw
    public boolean a() {
        return false;
    }

    @Override // io.openinstall.sdk.cw
    protected String b() {
        return "im";
    }

    @Override // io.openinstall.sdk.cw
    protected String c() {
        return "xefb";
    }

    @Override // io.openinstall.sdk.cw
    protected String d() {
        if (Configuration.isPresent(this.a.getImei())) {
            return this.a.getImei();
        }
        if (this.a.isImeiDisabled()) {
            return null;
        }
        return this.b.b();
    }
}
