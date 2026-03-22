package p476m.p496b.p497a;

import java.util.logging.Level;

/* renamed from: m.b.a.b */
/* loaded from: classes3.dex */
public final class RunnableC4908b implements Runnable, InterfaceC4918l {

    /* renamed from: c */
    public final C4917k f12505c = new C4917k();

    /* renamed from: e */
    public final C4909c f12506e;

    /* renamed from: f */
    public volatile boolean f12507f;

    public RunnableC4908b(C4909c c4909c) {
        this.f12506e = c4909c;
    }

    @Override // p476m.p496b.p497a.InterfaceC4918l
    /* renamed from: a */
    public void mo5567a(C4923q c4923q, Object obj) {
        C4916j m5584a = C4916j.m5584a(c4923q, obj);
        synchronized (this) {
            this.f12505c.m5585a(m5584a);
            if (!this.f12507f) {
                this.f12507f = true;
                this.f12506e.f12520m.execute(this);
            }
        }
    }

    @Override // java.lang.Runnable
    public void run() {
        C4916j m5586b;
        while (true) {
            try {
                C4917k c4917k = this.f12505c;
                synchronized (c4917k) {
                    if (c4917k.f12548a == null) {
                        c4917k.wait(1000);
                    }
                    m5586b = c4917k.m5586b();
                }
                if (m5586b == null) {
                    synchronized (this) {
                        m5586b = this.f12505c.m5586b();
                        if (m5586b == null) {
                            return;
                        }
                    }
                }
                this.f12506e.m5570c(m5586b);
            } catch (InterruptedException e2) {
                this.f12506e.f12526s.mo5582b(Level.WARNING, Thread.currentThread().getName() + " was interruppted", e2);
                return;
            } finally {
                this.f12507f = false;
            }
        }
    }
}
