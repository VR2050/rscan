package p379c.p380a;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2964m;

/* renamed from: c.a.l1 */
/* loaded from: classes2.dex */
public abstract class AbstractC3077l1 extends AbstractC3036c0 {
    @NotNull
    /* renamed from: U */
    public abstract AbstractC3077l1 mo3620U();

    @Nullable
    /* renamed from: V */
    public final String m3621V() {
        AbstractC3077l1 abstractC3077l1;
        AbstractC3036c0 abstractC3036c0 = C3079m0.f8430a;
        AbstractC3077l1 abstractC3077l12 = C2964m.f8127b;
        if (this == abstractC3077l12) {
            return "Dispatchers.Main";
        }
        try {
            abstractC3077l1 = abstractC3077l12.mo3620U();
        } catch (UnsupportedOperationException unused) {
            abstractC3077l1 = null;
        }
        if (this == abstractC3077l1) {
            return "Dispatchers.Main.immediate";
        }
        return null;
    }

    @Override // p379c.p380a.AbstractC3036c0
    @NotNull
    public String toString() {
        String m3621V = m3621V();
        if (m3621V != null) {
            return m3621V;
        }
        return getClass().getSimpleName() + '@' + C2354n.m2495m0(this);
    }
}
