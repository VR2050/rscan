package p005b.p199l.p200a.p201a.p227k1.p230l0;

import p005b.p199l.p200a.p201a.p208f1.C1980c;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2151h;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.l0.g */
/* loaded from: classes.dex */
public final class C2140g implements InterfaceC2139f {

    /* renamed from: a */
    public final C1980c f4729a;

    /* renamed from: b */
    public final long f4730b;

    public C2140g(C1980c c1980c, long j2) {
        this.f4729a = c1980c;
        this.f4730b = j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
    /* renamed from: a */
    public long mo1867a(long j2) {
        return this.f4729a.f3582e[(int) j2] - this.f4730b;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
    /* renamed from: b */
    public long mo1868b(long j2, long j3) {
        return this.f4729a.f3581d[(int) j2];
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
    /* renamed from: c */
    public C2151h mo1869c(long j2) {
        return new C2151h(null, this.f4729a.f3580c[(int) j2], r0.f3579b[r9]);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
    /* renamed from: d */
    public long mo1870d(long j2, long j3) {
        C1980c c1980c = this.f4729a;
        return C2344d0.m2326d(c1980c.f3582e, j2 + this.f4730b, true, true);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
    /* renamed from: e */
    public boolean mo1871e() {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
    /* renamed from: f */
    public long mo1872f() {
        return 0L;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f
    /* renamed from: g */
    public int mo1873g(long j2) {
        return this.f4729a.f3578a;
    }
}
