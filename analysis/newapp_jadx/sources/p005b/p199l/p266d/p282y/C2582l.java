package p005b.p199l.p266d.p282y;

import java.util.Map;
import p005b.p199l.p266d.C2521c;
import p005b.p199l.p266d.C2525g;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.EnumC2535q;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.l */
/* loaded from: classes2.dex */
public final class C2582l extends AbstractC2586p {

    /* renamed from: h */
    public final AbstractC2586p f7047h = new C2575e();

    /* renamed from: o */
    public static C2534p m3017o(C2534p c2534p) {
        String str = c2534p.f6854a;
        if (str.charAt(0) != '0') {
            throw C2525g.m2925a();
        }
        C2534p c2534p2 = new C2534p(str.substring(1), null, c2534p.f6856c, EnumC2497a.UPC_A);
        Map<EnumC2535q, Object> map = c2534p.f6858e;
        if (map != null) {
            c2534p2.m2932a(map);
        }
        return c2534p2;
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k, p005b.p199l.p266d.InterfaceC2532n
    /* renamed from: a */
    public C2534p mo2867a(C2521c c2521c, Map<EnumC2523e, ?> map) {
        return m3017o(this.f7047h.mo2867a(c2521c, map));
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p, p005b.p199l.p266d.p282y.AbstractC2581k
    /* renamed from: b */
    public C2534p mo3000b(int i2, C2543a c2543a, Map<EnumC2523e, ?> map) {
        return m3017o(this.f7047h.mo3000b(i2, c2543a, map));
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: j */
    public int mo3006j(C2543a c2543a, int[] iArr, StringBuilder sb) {
        return this.f7047h.mo3006j(c2543a, iArr, sb);
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: k */
    public C2534p mo3018k(int i2, C2543a c2543a, int[] iArr, Map<EnumC2523e, ?> map) {
        return m3017o(this.f7047h.mo3018k(i2, c2543a, iArr, map));
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: n */
    public EnumC2497a mo3007n() {
        return EnumC2497a.UPC_A;
    }
}
