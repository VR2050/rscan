package p005b.p199l.p266d.p282y;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import p005b.p199l.p266d.AbstractC2533o;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.j */
/* loaded from: classes2.dex */
public final class C2580j extends AbstractC2581k {

    /* renamed from: a */
    public static final AbstractC2586p[] f7045a = new AbstractC2586p[0];

    /* renamed from: b */
    public final AbstractC2586p[] f7046b;

    public C2580j(Map<EnumC2523e, ?> map) {
        Collection collection = map == null ? null : (Collection) map.get(EnumC2523e.POSSIBLE_FORMATS);
        ArrayList arrayList = new ArrayList();
        if (collection != null) {
            if (collection.contains(EnumC2497a.EAN_13)) {
                arrayList.add(new C2575e());
            } else if (collection.contains(EnumC2497a.UPC_A)) {
                arrayList.add(new C2582l());
            }
            if (collection.contains(EnumC2497a.EAN_8)) {
                arrayList.add(new C2576f());
            }
            if (collection.contains(EnumC2497a.UPC_E)) {
                arrayList.add(new C2587q());
            }
        }
        if (arrayList.isEmpty()) {
            arrayList.add(new C2575e());
            arrayList.add(new C2576f());
            arrayList.add(new C2587q());
        }
        this.f7046b = (AbstractC2586p[]) arrayList.toArray(f7045a);
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k
    /* renamed from: b */
    public C2534p mo3000b(int i2, C2543a c2543a, Map<EnumC2523e, ?> map) {
        boolean z;
        EnumC2497a enumC2497a = EnumC2497a.UPC_A;
        int[] m3023m = AbstractC2586p.m3023m(c2543a);
        for (AbstractC2586p abstractC2586p : this.f7046b) {
            try {
                C2534p mo3018k = abstractC2586p.mo3018k(i2, c2543a, m3023m, map);
                boolean z2 = mo3018k.f6857d == EnumC2497a.EAN_13 && mo3018k.f6854a.charAt(0) == '0';
                Collection collection = map == null ? null : (Collection) map.get(EnumC2523e.POSSIBLE_FORMATS);
                if (collection != null && !collection.contains(enumC2497a)) {
                    z = false;
                    if (z2 || !z) {
                        return mo3018k;
                    }
                    C2534p c2534p = new C2534p(mo3018k.f6854a.substring(1), mo3018k.f6855b, mo3018k.f6856c, enumC2497a);
                    c2534p.m2932a(mo3018k.f6858e);
                    return c2534p;
                }
                z = true;
                if (z2) {
                }
                return mo3018k;
            } catch (AbstractC2533o unused) {
            }
        }
        throw C2529k.f6843f;
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k, p005b.p199l.p266d.InterfaceC2532n
    public void reset() {
        for (AbstractC2586p abstractC2586p : this.f7046b) {
            Objects.requireNonNull(abstractC2586p);
        }
    }
}
