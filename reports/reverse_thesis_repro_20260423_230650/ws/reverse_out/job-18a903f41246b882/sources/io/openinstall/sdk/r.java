package io.openinstall.sdk;

import android.content.Context;
import com.fm.openinstall.Configuration;

/* JADX INFO: loaded from: classes3.dex */
public class r extends cw {
    private final Context a;
    private final Configuration b;

    public r(Context context, Configuration configuration) {
        this.a = context;
        this.b = configuration;
    }

    @Override // io.openinstall.sdk.cw
    public boolean a() {
        return !this.b.isSimulatorDisabled();
    }

    @Override // io.openinstall.sdk.cw
    protected String b() {
        return "si";
    }

    @Override // io.openinstall.sdk.cw
    protected String c() {
        return "bnwp";
    }

    @Override // io.openinstall.sdk.cw
    protected String d() {
        if (this.b.isSimulatorDisabled() || !k.a().a(this.a)) {
            return null;
        }
        if (ec.a) {
            ec.b("您正在使用模拟器测试，将不会统计数据", new Object[0]);
        }
        return String.valueOf(true);
    }
}
