package p005b.p199l.p200a.p201a;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2365y;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p;

/* renamed from: b.l.a.a.z */
/* loaded from: classes.dex */
public final class C2407z implements InterfaceC2356p {

    /* renamed from: c */
    public final C2365y f6396c;

    /* renamed from: e */
    public final a f6397e;

    /* renamed from: f */
    @Nullable
    public InterfaceC2396t0 f6398f;

    /* renamed from: g */
    @Nullable
    public InterfaceC2356p f6399g;

    /* renamed from: h */
    public boolean f6400h = true;

    /* renamed from: i */
    public boolean f6401i;

    /* renamed from: b.l.a.a.z$a */
    public interface a {
    }

    public C2407z(a aVar, InterfaceC2346f interfaceC2346f) {
        this.f6397e = aVar;
        this.f6396c = new C2365y(interfaceC2346f);
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p
    /* renamed from: b */
    public C2262n0 mo1312b() {
        InterfaceC2356p interfaceC2356p = this.f6399g;
        return interfaceC2356p != null ? interfaceC2356p.mo1312b() : this.f6396c.f6156h;
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p
    /* renamed from: i */
    public long mo1317i() {
        return this.f6400h ? this.f6396c.mo1317i() : this.f6399g.mo1317i();
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2356p
    /* renamed from: s */
    public void mo1324s(C2262n0 c2262n0) {
        InterfaceC2356p interfaceC2356p = this.f6399g;
        if (interfaceC2356p != null) {
            interfaceC2356p.mo1324s(c2262n0);
            c2262n0 = this.f6399g.mo1312b();
        }
        this.f6396c.mo1324s(c2262n0);
    }
}
