package io.openinstall.sdk;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

/* JADX INFO: loaded from: classes3.dex */
public abstract class av {
    private final Handler f = new Handler(Looper.getMainLooper());
    private final Context a = as.a().c();
    private final aq d = new aq();
    private final aw e = new aw();
    private final at c = new at(new ax().a(this.a, "FM_config", null));
    private final ck b = ck.a(this);
    private final bs g = a();

    protected av() {
        as.a().c(this.c.i());
    }

    protected abstract bs a();

    public Handler b() {
        return this.f;
    }

    public ck c() {
        return this.b;
    }

    public at d() {
        return this.c;
    }

    public aq e() {
        return this.d;
    }

    public aw f() {
        return this.e;
    }

    public ay g() {
        return ay.a(this.a, this.c);
    }

    public bv h() {
        return bv.a(this.a);
    }

    public bq i() {
        return bq.a(this.g);
    }
}
