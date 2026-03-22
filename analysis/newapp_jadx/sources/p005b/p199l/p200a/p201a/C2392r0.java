package p005b.p199l.p200a.p201a;

import android.os.Handler;
import androidx.annotation.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.r0 */
/* loaded from: classes.dex */
public final class C2392r0 {

    /* renamed from: a */
    public final b f6294a;

    /* renamed from: b */
    public final a f6295b;

    /* renamed from: c */
    public final AbstractC2404x0 f6296c;

    /* renamed from: d */
    public int f6297d;

    /* renamed from: e */
    @Nullable
    public Object f6298e;

    /* renamed from: f */
    public Handler f6299f;

    /* renamed from: g */
    public int f6300g;

    /* renamed from: h */
    public boolean f6301h;

    /* renamed from: i */
    public boolean f6302i;

    /* renamed from: j */
    public boolean f6303j;

    /* renamed from: b.l.a.a.r0$a */
    public interface a {
    }

    /* renamed from: b.l.a.a.r0$b */
    public interface b {
        /* renamed from: k */
        void mo1318k(int i2, @Nullable Object obj);
    }

    public C2392r0(a aVar, b bVar, AbstractC2404x0 abstractC2404x0, int i2, Handler handler) {
        this.f6295b = aVar;
        this.f6294a = bVar;
        this.f6296c = abstractC2404x0;
        this.f6299f = handler;
        this.f6300g = i2;
    }

    /* renamed from: a */
    public synchronized boolean m2644a() {
        return false;
    }

    /* renamed from: b */
    public synchronized void m2645b(boolean z) {
        this.f6302i = z | this.f6302i;
        this.f6303j = true;
        notifyAll();
    }

    /* renamed from: c */
    public C2392r0 m2646c() {
        C4195m.m4771I(!this.f6301h);
        C4195m.m4765F(true);
        this.f6301h = true;
        C1949d0 c1949d0 = (C1949d0) this.f6295b;
        synchronized (c1949d0) {
            if (!c1949d0.f3364z && c1949d0.f3349k.isAlive()) {
                c1949d0.f3348j.m2298b(15, this).sendToTarget();
            }
            m2645b(false);
        }
        return this;
    }

    /* renamed from: d */
    public C2392r0 m2647d(@Nullable Object obj) {
        C4195m.m4771I(!this.f6301h);
        this.f6298e = obj;
        return this;
    }

    /* renamed from: e */
    public C2392r0 m2648e(int i2) {
        C4195m.m4771I(!this.f6301h);
        this.f6297d = i2;
        return this;
    }
}
