package p005b.p199l.p200a.p201a.p250p1;

import p005b.p199l.p200a.p201a.C2262n0;
import p005b.p199l.p200a.p201a.C2399v;

/* renamed from: b.l.a.a.p1.y */
/* loaded from: classes.dex */
public final class C2365y implements InterfaceC2356p {

    /* renamed from: c */
    public final InterfaceC2346f f6152c;

    /* renamed from: e */
    public boolean f6153e;

    /* renamed from: f */
    public long f6154f;

    /* renamed from: g */
    public long f6155g;

    /* renamed from: h */
    public C2262n0 f6156h = C2262n0.f5668a;

    public C2365y(InterfaceC2346f interfaceC2346f) {
        this.f6152c = interfaceC2346f;
    }

    /* renamed from: a */
    public void m2608a(long j2) {
        this.f6154f = j2;
        if (this.f6153e) {
            this.f6155g = this.f6152c.mo2354c();
        }
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p
    /* renamed from: b */
    public C2262n0 mo1312b() {
        return this.f6156h;
    }

    /* renamed from: c */
    public void m2609c() {
        if (this.f6153e) {
            return;
        }
        this.f6155g = this.f6152c.mo2354c();
        this.f6153e = true;
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p
    /* renamed from: i */
    public long mo1317i() {
        long j2 = this.f6154f;
        if (!this.f6153e) {
            return j2;
        }
        long mo2354c = this.f6152c.mo2354c() - this.f6155g;
        return this.f6156h.f5669b == 1.0f ? j2 + C2399v.m2668a(mo2354c) : j2 + (mo2354c * r4.f5672e);
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p
    /* renamed from: s */
    public void mo1324s(C2262n0 c2262n0) {
        if (this.f6153e) {
            m2608a(mo1317i());
        }
        this.f6156h = c2262n0;
    }
}
