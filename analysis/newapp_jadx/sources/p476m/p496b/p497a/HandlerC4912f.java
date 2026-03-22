package p476m.p496b.p497a;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.SystemClock;

/* renamed from: m.b.a.f */
/* loaded from: classes3.dex */
public class HandlerC4912f extends Handler implements InterfaceC4918l {

    /* renamed from: c */
    public final C4917k f12533c;

    /* renamed from: e */
    public final int f12534e;

    /* renamed from: f */
    public final C4909c f12535f;

    /* renamed from: g */
    public boolean f12536g;

    public HandlerC4912f(C4909c c4909c, Looper looper, int i2) {
        super(looper);
        this.f12535f = c4909c;
        this.f12534e = i2;
        this.f12533c = new C4917k();
    }

    @Override // p476m.p496b.p497a.InterfaceC4918l
    /* renamed from: a */
    public void mo5567a(C4923q c4923q, Object obj) {
        C4916j m5584a = C4916j.m5584a(c4923q, obj);
        synchronized (this) {
            this.f12533c.m5585a(m5584a);
            if (!this.f12536g) {
                this.f12536g = true;
                if (!sendMessage(obtainMessage())) {
                    throw new C4911e("Could not send handler message");
                }
            }
        }
    }

    @Override // android.os.Handler
    public void handleMessage(Message message) {
        try {
            long uptimeMillis = SystemClock.uptimeMillis();
            do {
                C4916j m5586b = this.f12533c.m5586b();
                if (m5586b == null) {
                    synchronized (this) {
                        m5586b = this.f12533c.m5586b();
                        if (m5586b == null) {
                            this.f12536g = false;
                            return;
                        }
                    }
                }
                this.f12535f.m5570c(m5586b);
            } while (SystemClock.uptimeMillis() - uptimeMillis < this.f12534e);
            if (!sendMessage(obtainMessage())) {
                throw new C4911e("Could not send handler message");
            }
            this.f12536g = true;
        } finally {
            this.f12536g = false;
        }
    }
}
