package io.openinstall.sdk;

import java.util.concurrent.ThreadPoolExecutor;

/* JADX INFO: loaded from: classes3.dex */
public abstract class cs {
    protected final av a;
    protected final da b;

    public cs(av avVar, da daVar) {
        this.a = avVar;
        this.b = daVar;
    }

    protected String a() {
        return as.a().e();
    }

    protected aq b() {
        return this.a.e();
    }

    protected at c() {
        return this.a.d();
    }

    protected aw d() {
        return this.a.f();
    }

    protected ck e() {
        return this.a.c();
    }

    protected ay f() {
        return this.a.g();
    }

    protected bq g() {
        return this.a.i();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public bv h() {
        return this.a.h();
    }

    protected ThreadPoolExecutor i() {
        return db.a();
    }

    protected ThreadPoolExecutor j() {
        return db.b();
    }

    protected abstract String k();

    public void l() {
        m();
        j().execute(new ct(this));
    }

    protected void m() {
    }

    protected abstract cy n();
}
