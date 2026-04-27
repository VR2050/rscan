package io.openinstall.sdk;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;

/* JADX INFO: loaded from: classes3.dex */
public class bo extends Handler {
    protected aq a;
    protected aw b;
    protected ck c;
    protected at d;
    private final bi e;
    private long f;
    private int g;

    public bo(Looper looper, av avVar) {
        super(looper);
        this.g = 0;
        this.a = avVar.e();
        this.b = avVar.f();
        this.c = avVar.c();
        this.d = avVar.d();
        this.e = new bi(b(), c());
        this.f = this.d.d();
    }

    private void a(boolean z) throws Throwable {
        if (z || b(false)) {
            f();
        }
    }

    private Context b() {
        return as.a().c();
    }

    private boolean b(be beVar) {
        if (beVar.b() == 2 && !this.b.f()) {
            if (ec.a) {
                ec.b("eventStatsEnabled is false", new Object[0]);
            }
            return false;
        }
        if (beVar.b() == 1 && !this.b.f()) {
            if (ec.a) {
                ec.b("eventStatsEnabled is false", new Object[0]);
            }
            return false;
        }
        if (beVar.b() != 0 || this.b.d()) {
            return true;
        }
        if (ec.a) {
            ec.b("registerStatsEnabled is false", new Object[0]);
        }
        return false;
    }

    private boolean b(boolean z) {
        if (!this.a.c()) {
            if (!z) {
                this.a.a();
            }
            return false;
        }
        if (z) {
            if (!this.b.f() && !this.b.d()) {
                this.e.d();
                return false;
            }
            if (this.e.a()) {
                return false;
            }
        }
        if (this.e.b()) {
            return true;
        }
        return this.b.g() * 1000 < System.currentTimeMillis() - this.f;
    }

    private String c() {
        return as.a().e();
    }

    private void c(be beVar) throws Throwable {
        boolean zC;
        if (b(beVar)) {
            this.e.a(beVar);
            zC = beVar.c();
        } else {
            zC = false;
        }
        a(zC);
    }

    private void d() {
        this.g = 0;
    }

    private void e() {
        int i = this.g;
        if (i < 10) {
            this.g = i + 1;
        }
    }

    private void f() throws Throwable {
        if (!this.a.b()) {
            this.a.a();
            return;
        }
        cr crVarB = this.c.b(this.e.e());
        this.f = System.currentTimeMillis();
        if (!crVarB.a()) {
            if (ec.a) {
                ec.c("statEvents fail : %s", crVarB.c());
            }
            e();
        } else {
            if (crVarB.e().a() == 0) {
                if (ec.a) {
                    ec.a("statEvents success", new Object[0]);
                }
                d();
                this.e.c();
            }
            this.d.a(this.f);
        }
    }

    public void a() {
        Message messageObtain = Message.obtain();
        messageObtain.what = 23;
        messageObtain.obj = null;
        sendMessage(messageObtain);
    }

    public void a(be beVar) {
        Message messageObtain = Message.obtain();
        messageObtain.what = 21;
        messageObtain.obj = beVar;
        sendMessage(messageObtain);
    }

    @Override // android.os.Handler
    public void handleMessage(Message message) throws Throwable {
        if (message.what == 21) {
            c((be) message.obj);
        } else if (message.what == 23 && this.g < 10 && b(true)) {
            f();
        }
    }
}
