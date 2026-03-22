package p005b.p199l.p200a.p201a.p208f1.p215g0;

import p005b.p199l.p200a.p201a.p208f1.C2051r;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.f1.g0.d */
/* loaded from: classes.dex */
public final class C2040d implements InterfaceC2050q {

    /* renamed from: a */
    public final C2038b f4161a;

    /* renamed from: b */
    public final int f4162b;

    /* renamed from: c */
    public final long f4163c;

    /* renamed from: d */
    public final long f4164d;

    /* renamed from: e */
    public final long f4165e;

    public C2040d(C2038b c2038b, int i2, long j2, long j3) {
        this.f4161a = c2038b;
        this.f4162b = i2;
        this.f4163c = j2;
        long j4 = (j3 - j2) / c2038b.f4156d;
        this.f4164d = j4;
        this.f4165e = m1622d(j4);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: c */
    public boolean mo1462c() {
        return true;
    }

    /* renamed from: d */
    public final long m1622d(long j2) {
        return C2344d0.m2314F(j2 * this.f4162b, 1000000L, this.f4161a.f4155c);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: g */
    public InterfaceC2050q.a mo1463g(long j2) {
        long m2330h = C2344d0.m2330h((this.f4161a.f4155c * j2) / (this.f4162b * 1000000), 0L, this.f4164d - 1);
        long j3 = (this.f4161a.f4156d * m2330h) + this.f4163c;
        long m1622d = m1622d(m2330h);
        C2051r c2051r = new C2051r(m1622d, j3);
        if (m1622d >= j2 || m2330h == this.f4164d - 1) {
            return new InterfaceC2050q.a(c2051r);
        }
        long j4 = m2330h + 1;
        return new InterfaceC2050q.a(c2051r, new C2051r(m1622d(j4), (this.f4161a.f4156d * j4) + this.f4163c));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q
    /* renamed from: i */
    public long mo1464i() {
        return this.f4165e;
    }
}
