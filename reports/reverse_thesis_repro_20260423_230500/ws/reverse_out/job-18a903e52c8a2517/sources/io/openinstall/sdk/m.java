package io.openinstall.sdk;

import android.content.Context;
import com.fm.openinstall.Configuration;
import io.openinstall.sdk.t;

/* JADX INFO: loaded from: classes3.dex */
public class m extends cw {
    private final Context a;
    private final Configuration b;

    public m(Context context, Configuration configuration) {
        this.a = context;
        this.b = configuration;
    }

    @Override // io.openinstall.sdk.cw
    public boolean a() {
        return !Configuration.isPresent(this.b.getGaid());
    }

    @Override // io.openinstall.sdk.cw
    protected String b() {
        return "ga";
    }

    @Override // io.openinstall.sdk.cw
    protected String c() {
        return "feem";
    }

    @Override // io.openinstall.sdk.cw
    protected String d() {
        if (Configuration.isPresent(this.b.getGaid())) {
            return this.b.getGaid();
        }
        t.a aVarA = t.a(this.a);
        if (aVarA == null || aVarA.b()) {
            return null;
        }
        return aVarA.a();
    }
}
