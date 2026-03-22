package p005b.p295o.p296a.p297a;

import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.o.a.a.a */
/* loaded from: classes2.dex */
public class C2673a implements InterfaceC2684l, InterfaceC2683k {

    /* renamed from: b */
    public C2676d f7269b = null;

    /* renamed from: c */
    public final C2675c f7270c = new C2675c();

    /* renamed from: d */
    public InterfaceC2684l f7271d = null;

    /* renamed from: a */
    public void m3165a(char[] cArr, int i2, int i3) {
        C2676d c2676d = this.f7269b;
        AbstractC2678f abstractC2678f = c2676d.f7276g;
        if (!(abstractC2678f instanceof C2686n)) {
            c2676d.m3177g(new C2686n(new String(cArr, i2, i3)));
            return;
        }
        C2686n c2686n = (C2686n) abstractC2678f;
        c2686n.f7341f.append(cArr, i2, i3);
        c2686n.mo3170c();
    }

    @Override // p005b.p295o.p296a.p297a.InterfaceC2684l
    public String toString() {
        if (this.f7271d == null) {
            return null;
        }
        StringBuilder m586H = C1499a.m586H("BuildDoc: ");
        m586H.append(this.f7271d.toString());
        return m586H.toString();
    }
}
