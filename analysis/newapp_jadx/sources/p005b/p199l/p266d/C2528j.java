package p005b.p199l.p266d;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import p005b.p199l.p266d.p267a0.C2498a;
import p005b.p199l.p266d.p271u.C2540b;
import p005b.p199l.p266d.p277w.C2560a;
import p005b.p199l.p266d.p280x.C2567a;
import p005b.p199l.p266d.p282y.C2579i;
import p005b.p199l.p266d.p286z.C2616b;

/* renamed from: b.l.d.j */
/* loaded from: classes2.dex */
public final class C2528j implements InterfaceC2532n {

    /* renamed from: a */
    public static final InterfaceC2532n[] f6840a = new InterfaceC2532n[0];

    /* renamed from: b */
    public Map<EnumC2523e, ?> f6841b;

    /* renamed from: c */
    public InterfaceC2532n[] f6842c;

    @Override // p005b.p199l.p266d.InterfaceC2532n
    /* renamed from: a */
    public C2534p mo2867a(C2521c c2521c, Map<EnumC2523e, ?> map) {
        m2931c(map);
        return m2930b(c2521c);
    }

    /* renamed from: b */
    public final C2534p m2930b(C2521c c2521c) {
        InterfaceC2532n[] interfaceC2532nArr = this.f6842c;
        if (interfaceC2532nArr != null) {
            for (InterfaceC2532n interfaceC2532n : interfaceC2532nArr) {
                try {
                    return interfaceC2532n.mo2867a(c2521c, this.f6841b);
                } catch (AbstractC2533o unused) {
                }
            }
        }
        throw C2529k.f6843f;
    }

    /* renamed from: c */
    public void m2931c(Map<EnumC2523e, ?> map) {
        this.f6841b = map;
        boolean z = map != null && map.containsKey(EnumC2523e.TRY_HARDER);
        Collection collection = map == null ? null : (Collection) map.get(EnumC2523e.POSSIBLE_FORMATS);
        ArrayList arrayList = new ArrayList();
        if (collection != null) {
            boolean z2 = collection.contains(EnumC2497a.UPC_A) || collection.contains(EnumC2497a.UPC_E) || collection.contains(EnumC2497a.EAN_13) || collection.contains(EnumC2497a.EAN_8) || collection.contains(EnumC2497a.CODABAR) || collection.contains(EnumC2497a.CODE_39) || collection.contains(EnumC2497a.CODE_93) || collection.contains(EnumC2497a.CODE_128) || collection.contains(EnumC2497a.ITF) || collection.contains(EnumC2497a.RSS_14) || collection.contains(EnumC2497a.RSS_EXPANDED);
            if (z2 && !z) {
                arrayList.add(new C2579i(map));
            }
            if (collection.contains(EnumC2497a.QR_CODE)) {
                arrayList.add(new C2498a());
            }
            if (collection.contains(EnumC2497a.DATA_MATRIX)) {
                arrayList.add(new C2560a());
            }
            if (collection.contains(EnumC2497a.AZTEC)) {
                arrayList.add(new C2540b());
            }
            if (collection.contains(EnumC2497a.PDF_417)) {
                arrayList.add(new C2616b());
            }
            if (collection.contains(EnumC2497a.MAXICODE)) {
                arrayList.add(new C2567a());
            }
            if (z2 && z) {
                arrayList.add(new C2579i(map));
            }
        }
        if (arrayList.isEmpty()) {
            if (!z) {
                arrayList.add(new C2579i(map));
            }
            arrayList.add(new C2498a());
            arrayList.add(new C2560a());
            arrayList.add(new C2540b());
            arrayList.add(new C2616b());
            arrayList.add(new C2567a());
            if (z) {
                arrayList.add(new C2579i(map));
            }
        }
        this.f6842c = (InterfaceC2532n[]) arrayList.toArray(f6840a);
    }

    @Override // p005b.p199l.p266d.InterfaceC2532n
    public void reset() {
        InterfaceC2532n[] interfaceC2532nArr = this.f6842c;
        if (interfaceC2532nArr != null) {
            for (InterfaceC2532n interfaceC2532n : interfaceC2532nArr) {
                interfaceC2532n.reset();
            }
        }
    }
}
