package io.openinstall.sdk;

import android.content.Context;

/* JADX INFO: loaded from: classes3.dex */
public class o extends cw {
    private final Context a;

    public o(Context context) {
        this.a = context;
    }

    @Override // io.openinstall.sdk.cw
    public boolean a() {
        return true;
    }

    @Override // io.openinstall.sdk.cw
    protected String b() {
        return "gR";
    }

    @Override // io.openinstall.sdk.cw
    protected String c() {
        return "nosw";
    }

    @Override // io.openinstall.sdk.cw
    protected String d() {
        v vVar = new v();
        vVar.a(this.a);
        return vVar.a();
    }
}
