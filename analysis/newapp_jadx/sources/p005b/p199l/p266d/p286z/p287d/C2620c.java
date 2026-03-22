package p005b.p199l.p266d.p286z.p287d;

import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.p274v.C2544b;

/* renamed from: b.l.d.z.d.c */
/* loaded from: classes2.dex */
public final class C2620c {

    /* renamed from: a */
    public final C2544b f7138a;

    /* renamed from: b */
    public final C2536r f7139b;

    /* renamed from: c */
    public final C2536r f7140c;

    /* renamed from: d */
    public final C2536r f7141d;

    /* renamed from: e */
    public final C2536r f7142e;

    /* renamed from: f */
    public final int f7143f;

    /* renamed from: g */
    public final int f7144g;

    /* renamed from: h */
    public final int f7145h;

    /* renamed from: i */
    public final int f7146i;

    public C2620c(C2544b c2544b, C2536r c2536r, C2536r c2536r2, C2536r c2536r3, C2536r c2536r4) {
        boolean z = c2536r == null || c2536r2 == null;
        boolean z2 = c2536r3 == null || c2536r4 == null;
        if (z && z2) {
            throw C2529k.f6843f;
        }
        if (z) {
            c2536r = new C2536r(0.0f, c2536r3.f6872b);
            c2536r2 = new C2536r(0.0f, c2536r4.f6872b);
        } else if (z2) {
            int i2 = c2544b.f6893c;
            c2536r3 = new C2536r(i2 - 1, c2536r.f6872b);
            c2536r4 = new C2536r(i2 - 1, c2536r2.f6872b);
        }
        this.f7138a = c2544b;
        this.f7139b = c2536r;
        this.f7140c = c2536r2;
        this.f7141d = c2536r3;
        this.f7142e = c2536r4;
        this.f7143f = (int) Math.min(c2536r.f6871a, c2536r2.f6871a);
        this.f7144g = (int) Math.max(c2536r3.f6871a, c2536r4.f6871a);
        this.f7145h = (int) Math.min(c2536r.f6872b, c2536r3.f6872b);
        this.f7146i = (int) Math.max(c2536r2.f6872b, c2536r4.f6872b);
    }

    public C2620c(C2620c c2620c) {
        this.f7138a = c2620c.f7138a;
        this.f7139b = c2620c.f7139b;
        this.f7140c = c2620c.f7140c;
        this.f7141d = c2620c.f7141d;
        this.f7142e = c2620c.f7142e;
        this.f7143f = c2620c.f7143f;
        this.f7144g = c2620c.f7144g;
        this.f7145h = c2620c.f7145h;
        this.f7146i = c2620c.f7146i;
    }
}
