package p005b.p199l.p200a.p201a.p248o1;

import java.util.Arrays;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.q */
/* loaded from: classes.dex */
public final class C2325q implements InterfaceC2288e {

    /* renamed from: a */
    public final boolean f5942a;

    /* renamed from: b */
    public final int f5943b;

    /* renamed from: c */
    public final C2286d[] f5944c;

    /* renamed from: d */
    public int f5945d;

    /* renamed from: e */
    public int f5946e;

    /* renamed from: f */
    public int f5947f;

    /* renamed from: g */
    public C2286d[] f5948g;

    public C2325q(boolean z, int i2) {
        C4195m.m4765F(i2 > 0);
        C4195m.m4765F(true);
        this.f5942a = z;
        this.f5943b = i2;
        this.f5947f = 0;
        this.f5948g = new C2286d[100];
        this.f5944c = new C2286d[1];
    }

    /* renamed from: a */
    public synchronized void m2270a(C2286d[] c2286dArr) {
        int i2 = this.f5947f;
        int length = c2286dArr.length + i2;
        C2286d[] c2286dArr2 = this.f5948g;
        if (length >= c2286dArr2.length) {
            this.f5948g = (C2286d[]) Arrays.copyOf(c2286dArr2, Math.max(c2286dArr2.length * 2, i2 + c2286dArr.length));
        }
        for (C2286d c2286d : c2286dArr) {
            C2286d[] c2286dArr3 = this.f5948g;
            int i3 = this.f5947f;
            this.f5947f = i3 + 1;
            c2286dArr3[i3] = c2286d;
        }
        this.f5946e -= c2286dArr.length;
        notifyAll();
    }

    /* renamed from: b */
    public synchronized void m2271b(int i2) {
        boolean z = i2 < this.f5945d;
        this.f5945d = i2;
        if (z) {
            m2272c();
        }
    }

    /* renamed from: c */
    public synchronized void m2272c() {
        int max = Math.max(0, C2344d0.m2327e(this.f5945d, this.f5943b) - this.f5946e);
        int i2 = this.f5947f;
        if (max >= i2) {
            return;
        }
        Arrays.fill(this.f5948g, max, i2, (Object) null);
        this.f5947f = max;
    }
}
