package p005b.p199l.p266d.p282y;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import p005b.p199l.p266d.AbstractC2533o;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.p274v.C2543a;
import p005b.p199l.p266d.p282y.p283r.C2592e;
import p005b.p199l.p266d.p282y.p283r.p284f.C2595c;

/* renamed from: b.l.d.y.i */
/* loaded from: classes2.dex */
public final class C2579i extends AbstractC2581k {

    /* renamed from: a */
    public static final AbstractC2581k[] f7043a = new AbstractC2581k[0];

    /* renamed from: b */
    public final AbstractC2581k[] f7044b;

    public C2579i(Map<EnumC2523e, ?> map) {
        Collection collection = map == null ? null : (Collection) map.get(EnumC2523e.POSSIBLE_FORMATS);
        boolean z = (map == null || map.get(EnumC2523e.ASSUME_CODE_39_CHECK_DIGIT) == null) ? false : true;
        ArrayList arrayList = new ArrayList();
        if (collection != null) {
            if (collection.contains(EnumC2497a.EAN_13) || collection.contains(EnumC2497a.UPC_A) || collection.contains(EnumC2497a.EAN_8) || collection.contains(EnumC2497a.UPC_E)) {
                arrayList.add(new C2580j(map));
            }
            if (collection.contains(EnumC2497a.CODE_39)) {
                arrayList.add(new C2573c(z));
            }
            if (collection.contains(EnumC2497a.CODE_93)) {
                arrayList.add(new C2574d());
            }
            if (collection.contains(EnumC2497a.CODE_128)) {
                arrayList.add(new C2572b());
            }
            if (collection.contains(EnumC2497a.ITF)) {
                arrayList.add(new C2578h());
            }
            if (collection.contains(EnumC2497a.CODABAR)) {
                arrayList.add(new C2571a());
            }
            if (collection.contains(EnumC2497a.RSS_14)) {
                arrayList.add(new C2592e());
            }
            if (collection.contains(EnumC2497a.RSS_EXPANDED)) {
                arrayList.add(new C2595c());
            }
        }
        if (arrayList.isEmpty()) {
            arrayList.add(new C2580j(map));
            arrayList.add(new C2573c(false));
            arrayList.add(new C2571a());
            arrayList.add(new C2574d());
            arrayList.add(new C2572b());
            arrayList.add(new C2578h());
            arrayList.add(new C2592e());
            arrayList.add(new C2595c());
        }
        this.f7044b = (AbstractC2581k[]) arrayList.toArray(f7043a);
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k
    /* renamed from: b */
    public C2534p mo3000b(int i2, C2543a c2543a, Map<EnumC2523e, ?> map) {
        for (AbstractC2581k abstractC2581k : this.f7044b) {
            try {
                return abstractC2581k.mo3000b(i2, c2543a, map);
            } catch (AbstractC2533o unused) {
            }
        }
        throw C2529k.f6843f;
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k, p005b.p199l.p266d.InterfaceC2532n
    public void reset() {
        for (AbstractC2581k abstractC2581k : this.f7044b) {
            abstractC2581k.reset();
        }
    }
}
